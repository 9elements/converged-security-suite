package bootguard

import (
	"bytes"
	"fmt"
	"io"
	"os"

	"github.com/9elements/converged-security-suite/v2/pkg/tools"
	"github.com/linuxboot/fiano/pkg/intel/metadata/fit"
)

// WriteCBnTStructures takes a firmware image and extracts boot policy manifest, key manifest and acm into separate files.
func WriteCBnTStructures(image []byte, bpmFile, kmFile, acmFile *os.File) error {
	bpm, km, acm, err := ParseFITEntries(image)
	if err != nil && (bpm == nil && bpmFile != nil || km == nil && kmFile != nil || acm == nil && acmFile != nil) {
		return err
	}
	if bpmFile != nil && len(bpm.DataSegmentBytes) > 0 {
		if _, err = bpmFile.Write(bpm.DataSegmentBytes); err != nil {
			return err
		}
	}
	if kmFile != nil && len(km.DataSegmentBytes) > 0 {
		if _, err = kmFile.Write(km.DataSegmentBytes); err != nil {
			return err
		}
	}
	if acmFile != nil && len(acm.DataSegmentBytes) > 0 {
		if _, err = acmFile.Write(acm.DataSegmentBytes); err != nil {
			return err
		}
	}
	return nil
}

// PrintStructures takes a firmware image and prints boot policy manifest, key manifest, ACM, chipset, processor and tpm information if available.
func PrintStructures(image []byte) error {
	var acm *tools.ACM
	var err error
	bpmEntry, kmEntry, acmEntry, err := ParseFITEntries(image)
	if err != nil {
		return err
	}

	bpm, err := NewBPM(bpmEntry.Reader())
	if err != nil {
		return fmt.Errorf("unable to parse BPM: %w", err)
	}

	km, err := NewKM(kmEntry.Reader())
	if err != nil {
		return fmt.Errorf("unable to parse KM: %w", err)
	}

	acm, err = tools.ParseACM(bytes.NewReader(acmEntry.DataSegmentBytes))
	if err != nil {
		return err
	}
	km.PrintKM()
	bpm.PrintBPM()
	if acm != nil {
		acm.PrettyPrint()
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

// StitchFITEntries takes a firmware filename, an acm, a boot policy manifest and a key manifest as byte slices
// and writes the information into the Firmware Interface Table of the firmware image.
func StitchFITEntries(biosFilename string, acm, bpm, km []byte) error {
	image, err := os.ReadFile(biosFilename)
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
			if len(entry.DataSegmentBytes) == 0 {
				return fmt.Errorf("FIT entry size is zero for BPM")
			}
			if len(bpm) > len(entry.DataSegmentBytes) {
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
			if len(entry.DataSegmentBytes) == 0 {
				return fmt.Errorf("FIT entry size is zero for KM")
			}
			if len(km) > len(entry.DataSegmentBytes) {
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
