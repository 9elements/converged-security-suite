package bootguard

import (
	"os"

	"github.com/9elements/converged-security-suite/v2/pkg/provisioning/bootguard/bootpolicy"
	"github.com/linuxboot/cbfs/pkg/cbfs"
)

func WriteBGStructures(image []byte, bpmFile, kmFile, acmFile *os.File) error {
	bpm, km, acm, err := ParseFITEntries(image)
	if err != nil {
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

// FindAdditionalIBBs takes a coreboot image and finds componentName to create
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
	if err != nil {
		return nil, err
	}

	flashBase := 0xffffffff - stat.Size() + 1
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
