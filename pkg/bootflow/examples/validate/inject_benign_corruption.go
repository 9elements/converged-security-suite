package main

import (
	"bytes"
	"debug/pe"
	"fmt"
	"io/ioutil"
	"math"

	"github.com/9elements/converged-security-suite/v2/pkg/bootflow/bootengine/validator"
	"github.com/9elements/converged-security-suite/v2/pkg/bootflow/systemartifacts/biosimage"
	"github.com/9elements/converged-security-suite/v2/pkg/uefi/ffs"
	pkgbytes "github.com/linuxboot/fiano/pkg/bytes"
	"github.com/linuxboot/fiano/pkg/uefi"
)

func injectBenignCorruption(
	outputPath string,
	biosArtifact *biosimage.BIOSImage,
	coverageIssues validator.Issues,
) error {
	biosFW, err := biosArtifact.Parse()
	if err != nil {
		return fmt.Errorf("unable to parse the BIOS image: %w", err)
	}

	for _, issue := range coverageIssues {
		err, ok := issue.Issue.(validator.ErrNotFullCoverage)
		if !ok {
			continue
		}

		nonMeasured := err.NonMeasured
		biosNonMeasured := nonMeasured.BySystemArtifact(biosArtifact)
		if err := biosNonMeasured.Resolve(); err != nil {
			return fmt.Errorf("unable to resolve the references: %w", err)
		}

		for _, ref := range biosNonMeasured {
			for _, r := range ref.Ranges {
				nodes, err := biosFW.GetByRange(r)
				if err != nil {
					return fmt.Errorf("unable to get nodes related to range %s: %w", r, err)
				}

				reverseOrder(nodes)
				for _, node := range nodes {
					done, err := tryInjectBenignCorruptionToUEFINode(biosArtifact, node, r)
					if err != nil {
						return fmt.Errorf("unable to inject a corruption to %s: %w", node, err)
					}
					if done {
						return ioutil.WriteFile(outputPath, biosArtifact.Content, 0640)
					}
				}
			}
		}
	}

	return fmt.Errorf("unable to find a non-covered area which I know how to inject the corruption to")
}

func reverseOrder[E any](s []E) {
	for idx := 0; idx < len(s)/2; idx++ {
		s[idx], s[len(s)-1-idx] = s[len(s)-1-idx], s[idx]
	}
}

func tryInjectBenignCorruptionToUEFINode(
	biosArtifact *biosimage.BIOSImage,
	node *ffs.Node,
	allowedRange pkgbytes.Range,
) (bool, error) {
	var done bool
	visitor := &ffs.NodeVisitor{
		Callback: func(node ffs.Node) (bool, error) {
			if node.Range.Offset == math.MaxUint64 {
				return true, nil
			}
			if !node.Range.Intersect(allowedRange) {
				return true, nil
			}

			var err error
			switch obj := node.Firmware.(type) {
			case *uefi.File:
				done, err = tryInjectBenignCorruptionToUEFIFileContent(biosArtifact, obj, allowedRange)
				if !done && err == nil {
					attributesOffset := node.Offset + 16 + 2 + 1
					attributesIsAllowed := allowedRange.Intersect(pkgbytes.Range{
						Offset: attributesOffset,
						Length: 1,
					})
					if !attributesIsAllowed {
						break
					}
					if obj.Header.Attributes.HasChecksum() {
						biosArtifact.Content[attributesOffset] &= 0xff ^ 0x40
						done = true
						break
					}
					checksumOffset := node.Offset + 16
					checksumIsAllowed := len(pkgbytes.Range{
						Offset: checksumOffset,
						Length: 2,
					}.Exclude(allowedRange)) == 0
					if !checksumIsAllowed {
						break
					}

					obj.Header.Attributes |= 0x40
					if err := obj.ChecksumAndAssemble(obj.Buf()[obj.HeaderLen():]); err != nil {
						break
					}

					biosArtifact.Content[attributesOffset] |= 0x40
					biosArtifact.Content[checksumOffset] = obj.Header.Checksum.Header
					biosArtifact.Content[checksumOffset+1] = obj.Header.Checksum.File
					done = true
				}
			case *uefi.FirmwareVolume:
				reservedFieldOffset := node.Offset + 16 + 16 + 8 + 4 + 4 + 2 + 2 + 2
				if allowedRange.Intersect(pkgbytes.Range{
					Offset: reservedFieldOffset,
					Length: 1,
				}) {
					biosArtifact.Content[reservedFieldOffset]++
					done = true
				}
			}
			if err != nil {
				return false, fmt.Errorf("unable to inject a corruption to an %T '%s': %w", node.Firmware, node.GUID(), err)
			}
			return !done, nil
		},
	}

	err := visitor.Run(node)
	return done, err
}

func tryInjectBenignCorruptionToUEFIFileContent(
	biosArtifact *biosimage.BIOSImage,
	file *uefi.File,
	allowedRange pkgbytes.Range,
) (bool, error) {
	var done bool
	for idx, section := range file.Sections {
		switch section.Header.Type {
		case uefi.SectionTypePE32, uefi.SectionTypePIC, uefi.SectionTypeTE:
			var err error
			done, err = tryInjectBenignCorruptionToExecutable(biosArtifact, section, allowedRange)
			if err != nil {
				return false, fmt.Errorf("unable to inject a corruption to section %d of file %s: %w", idx, file.Header.GUID, err)
			}
		}
		if done {
			break
		}
	}
	return done, nil
}

func tryInjectBenignCorruptionToExecutable(
	biosArtifact *biosimage.BIOSImage,
	section *uefi.Section,
	allowedRange pkgbytes.Range,
) (bool, error) {
	switch section.Header.Type {
	case uefi.SectionTypePE32:
		peFile, err := pe.NewFile(bytes.NewReader(section.Buf()))
		if err != nil {
			return false, fmt.Errorf("unable to open the file as PE: %w", err)
		}
		// TODO: implement this, meanwhile:
		panic(fmt.Errorf("%#+v", *peFile))
	case uefi.SectionTypePIC:
		// not implemented, yet
		return false, nil
	case uefi.SectionTypeTE:
		// not implemented, yet
		return false, nil
	default:
		return false, fmt.Errorf("unexpected section type: %s", section.Header.Type)
	}
}
