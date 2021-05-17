package cbnt

import (
	"fmt"
	"io"
	"io/ioutil"
	"os"

	"github.com/9elements/converged-security-suite/v2/pkg/intel/metadata/fit"
	"github.com/9elements/converged-security-suite/v2/pkg/intel/metadata/manifest/bootpolicy"
	"github.com/9elements/converged-security-suite/v2/pkg/intel/metadata/manifest/common/pretty"
	"github.com/9elements/converged-security-suite/v2/pkg/intel/metadata/manifest/key"
	"github.com/9elements/converged-security-suite/v2/pkg/tools"
	"github.com/9elements/converged-security-suite/v2/pkg/uefi/consts"

	"github.com/linuxboot/cbfs/pkg/cbfs"
)

// WriteCBnTStructures takes a firmware image and extracts boot policy manifest, key manifest and acm into separate files.
func WriteCBnTStructures(image []byte, bpmFile, kmFile, acmFile *os.File) error {
	bpm, km, acm, err := ParseFITEntries(image)
	if err != nil && (bpm == nil && bpmFile != nil || km == nil && kmFile != nil || acm == nil && acmFile != nil) {
		return err
	}
	if bpmFile != nil && len(bpm.DataBytes) > 0 {
		if _, err = bpmFile.Write(bpm.DataBytes); err != nil {
			return err
		}
	}
	if kmFile != nil && len(km.DataBytes) > 0 {
		if _, err = kmFile.Write(km.DataBytes); err != nil {
			return err
		}
	}
	if acmFile != nil && len(acm.DataBytes) > 0 {
		if _, err = acmFile.Write(acm.DataBytes); err != nil {
			return err
		}
	}
	return nil
}

// PrintCBnTStructures takes a firmware image and prints boot policy manifest, key manifest, ACM, chipset, processor and tpm information if available.
func PrintCBnTStructures(image []byte) error {
	var acm *tools.ACM
	var chipsets *tools.Chipsets
	var processors *tools.Processors
	var tpms *tools.TPMs
	var err, err2 error
	bpmEntry, kmEntry, acmEntry, err := ParseFITEntries(image)
	if err != nil {
		return err
	}

	bpm, err := bpmEntry.ParseData()
	if err != nil {
		return fmt.Errorf("unable to parse BPM: %w", err)
	}

	km, err := kmEntry.ParseData()
	if err != nil {
		return fmt.Errorf("unable to parse KM: %w", err)
	}

	acm, chipsets, processors, tpms, err, err2 = tools.ParseACM(acmEntry.DataBytes)
	if err != nil || err2 != nil {
		return err
	}

	if bpm != nil {
		fmt.Println(bpm.PrettyString(0, true))
	}
	if km != nil {
		if km.KeyAndSignature.Signature.DataTotalSize() < 1 {
			fmt.Println(km.PrettyString(0, true, pretty.OptionOmitKeySignature(true)))
		} else {
			fmt.Println(km.PrettyString(0, true, pretty.OptionOmitKeySignature(false)))
		}
	}
	if acm != nil {
		acm.PrettyPrint()
		chipsets.PrettyPrint()
		processors.PrettyPrint()
		tpms.PrettyPrint()
	}
	return nil
}

// ParseFITEntries takes a firmware image and extract Boot policy manifest, key manifest and acm information.
func ParseFITEntries(image []byte) (bpm *fit.EntryBootPolicyManifestRecord, km *fit.EntryKeyManifestRecord, acm *fit.EntrySACM, err error) {
	fitTable, err := fit.GetTable(image)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("unable to get FIT: %w", err)
	}
	fitEntries := fitTable.GetEntries(image)
	for _, entry := range fitEntries {
		switch entry := entry.(type) {
		case *fit.EntryBootPolicyManifestRecord:
			bpm = entry
		case *fit.EntryKeyManifestRecord:
			km = entry
		case *fit.EntrySACM:
			acm = entry
		}
	}
	if bpm == nil || km == nil || acm == nil {
		return bpm, km, acm, fmt.Errorf("image has no BPM (isNil:%v) or/and KM (isNil:%v) or/and ACM (isNil:%v)", bpm == nil, km == nil, acm == nil)
	}
	return bpm, km, acm, nil
}

// CalculateNEMSize calculates No Eviction Memory and returns it as count of 4K pages.
func CalculateNEMSize(image []byte, bpm *bootpolicy.Manifest, km *key.Manifest, acm *tools.ACM) (bootpolicy.Size4K, error) {
	var totalSize uint32
	if bpm == nil || km == nil || acm == nil {
		return 0, fmt.Errorf("BPM, KM or ACM are nil")
	}
	fitTable, err := fit.GetTable(image)
	if err != nil {
		return 0, fmt.Errorf("unable to get FIT: %w", err)
	}
	fitEntries := fitTable.GetEntries(image)
	if len(fitEntries) == 0 || fitEntries[0].GetType() != fit.EntryTypeFITHeaderEntry {
		return 0, fmt.Errorf("unable to get FIT headers")
	}
	hdr := fitEntries[0]
	if err != nil {
		return 0, err
	}
	totalSize += uint32(km.KeyManifestSignatureOffset)
	totalSize += keySignatureElementMaxSize
	totalSize += hdr.GetHeaders().DataSize()
	totalSize += uint32(2048)
	totalSize += keySignatureElementMaxSize
	totalSize += uint32((&bootpolicy.BPMH{}).TotalSize())
	for _, se := range bpm.SE {
		totalSize += uint32(se.ElementSize)
		for _, ibb := range se.IBBSegments {
			totalSize += ibb.Size
		}
	}
	if bpm.PCDE != nil {
		totalSize += uint32(bpm.PCDE.ElementSize)
	}
	if bpm.PME != nil {
		totalSize += uint32(bpm.PME.ElementSize)
	}
	totalSize += uint32(12)
	totalSize += keySignatureElementMaxSize
	if bpm.TXTE != nil {
		totalSize += uint32(bpm.TXTE.ElementSize)
	}
	totalSize += acm.Header.Size
	totalSize += defaultStackAndDataSize
	if (totalSize + additionalNEMSize) > defaultLLCSize {
		return 0, fmt.Errorf("NEM size is bigger than LLC %d", totalSize+additionalNEMSize)
	}
	if (totalSize % 4096) != 0 {
		totalSize += 4096 - (totalSize % 4096)
	}
	return bootpolicy.NewSize4K(totalSize), nil
}

// StitchFITEntries takes a firmware filename, an acm, a boot policy manifest and a key manifest as byte slices
// and writes the information into the Firmware Interface Table of the firmware image.
func StitchFITEntries(biosFilename string, acm, bpm, km []byte) error {
	image, err := ioutil.ReadFile(biosFilename)
	if err != nil {
		return err
	}
	fitTable, err := fit.GetTable(image)
	if err != nil {
		return fmt.Errorf("unable to get FIT: %w", err)
	}
	fitEntries := fitTable.GetEntries(image)
	file, err := os.OpenFile(biosFilename, os.O_RDWR, 0600)
	if err != nil {
		return err
	}
	defer file.Close()
	for _, entry := range fitEntries {
		switch entry := entry.(type) {
		case *fit.EntryBootPolicyManifestRecord:
			if len(bpm) <= 0 {
				continue
			}
			if len(entry.DataBytes) == 0 {
				return fmt.Errorf("FIT entry size is zero for BPM")
			}
			if len(bpm) > len(entry.DataBytes) {
				return fmt.Errorf("new BPM bigger than older BPM")
			}
			addr, err := tools.CalcImageOffset(image, entry.Headers.Address.Pointer())
			if err != nil {
				return err
			}
			_, err = file.Seek(0, 0)
			if err != nil {
				return err
			}
			size, err := file.WriteAt(bpm, int64(addr))
			if err != nil {
				return err
			}
			if size != len(bpm) {
				return fmt.Errorf("couldn't write new BPM")
			}
		case *fit.EntryKeyManifestRecord:
			if len(km) <= 0 {
				continue
			}
			if len(entry.DataBytes) == 0 {
				return fmt.Errorf("FIT entry size is zero for KM")
			}
			if len(km) > len(entry.DataBytes) {
				return fmt.Errorf("new KM bigger than older KM")
			}
			addr, err := tools.CalcImageOffset(image, entry.Headers.Address.Pointer())
			if err != nil {
				return err
			}
			_, err = file.Seek(0, 0)
			if err != nil {
				return err
			}
			size, err := file.WriteAt(km, int64(addr))
			if err != nil {
				return err
			}
			if size != len(km) {
				return fmt.Errorf("couldn't write new KM")
			}
		case *fit.EntrySACM:
			if len(acm) <= 0 {
				continue
			}
			addr, err := tools.CalcImageOffset(image, entry.Headers.Address.Pointer())
			if err != nil {
				return err
			}
			_, err = file.Seek(int64(addr), io.SeekStart)
			if err != nil {
				return err
			}
			acmHeader := make([]byte, 32)
			_, err = file.Read(acmHeader)
			if err != nil {
				return err
			}
			acmLen, err := tools.LookupACMSize(acmHeader)
			if err != nil {
				return err
			}
			if acmLen == 0 {
				return fmt.Errorf("ACM size is wrong")
			}
			if len(acm) != int(acmLen) {
				return fmt.Errorf("new ACM size doesn't equal old ACM size")
			}
			_, err = file.Seek(0, 0)
			if err != nil {
				return err
			}
			size, err := file.WriteAt(acm, int64(addr))
			if err != nil {
				return err
			}
			if size != len(acm) {
				return fmt.Errorf("couldn't write new ACM")
			}
		}
	}
	return nil
}

// FindAdditionalIBBs takes a coreboot image, searches cbfs files for
// additional IBBSegment.
func FindAdditionalIBBs(imagepath string) ([]bootpolicy.IBBSegment, error) {
	ibbs := make([]bootpolicy.IBBSegment, 0)
	image, err := os.Open(imagepath)
	if err != nil {
		return nil, err
	}
	defer image.Close()

	stat, err := image.Stat()
	if err != nil {
		return nil, err
	}

	img, err := cbfs.NewImage(image)
	// If this returns an error, we assume it's an UEFI image
	if err != nil {
		// To be sure the image file is closed before reading from it again
		image.Close()
		img, err := ioutil.ReadFile(imagepath)
		if err != nil {
			return ibbs, err
		}
		fitentries, err := fit.GetEntries(img)
		if err != nil {
			return ibbs, err
		}
		for _, entry := range fitentries {
			if entry.GetType() == fit.EntryTypeBIOSStartupModuleEntry {
				ibb := bootpolicy.NewIBBSegment()
				ibb.Base = uint32(entry.GetHeaders().Address.Pointer())
				ibb.Size = entry.GetHeaders().Size.Uint32() << 4
				ibbs = append(ibbs, *ibb)
			}
		}
		return ibbs, nil
	}
	// From here we consider it is a coreboot image
	flashBase := consts.BasePhysAddr - stat.Size()
	cbfsbaseaddr := img.Area.Offset
	for _, seg := range img.Segs {
		switch seg.GetFile().Name {
		case
			"fspt.bin",
			"fallback/verstage",
			"bootblock":

			ibb := bootpolicy.NewIBBSegment()
			ibb.Base = uint32(flashBase) + cbfsbaseaddr + seg.GetFile().RecordStart + seg.GetFile().SubHeaderOffset
			ibb.Size = seg.GetFile().Size
			ibb.Flags = 0
			ibbs = append(ibbs, *ibb)
		}
	}
	return ibbs, nil
}
