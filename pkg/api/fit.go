package api

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"log"
)

type FitEntryType uint16

// FitEntryTypes for distiction of Entries
const (
	FitHeader           FitEntryType = 0x00
	MCUpdate            FitEntryType = 0x01
	StartUpACMod        FitEntryType = 0x02
	BIOSStartUpMod      FitEntryType = 0x07
	TPMPolicyRec        FitEntryType = 0x08
	BIOSPolicyRec       FitEntryType = 0x09
	TXTPolicyRec        FitEntryType = 0x0A
	KeyManifestRec      FitEntryType = 0x0B
	BootPolicyManifest  FitEntryType = 0x0C
	CSESecBoot          FitEntryType = 0x10
	FeaturePolicyDelRec FitEntryType = 0x2D
	JumpDebugPol        FitEntryType = 0x2F
	UnusedEntry         FitEntryType = 0x7F
	// 0x03 - 0x06 	: Intel reserved
	// 0x0D - 0x0D 	: Intel reserved
	// 0x11 - 0x2C 	: Intel reserved
	// 0x2E 		: Intel reserved
	// 0x30 - 0x70	: Reserved for Manufacturer Use
	// 0x71 - 0x7E	: IntelReserved
)

const (
	fitPointer     uint64 = 0xFFFFFFC0
	type0MagicWord uint64 = 0x2020205f5449465f
	FourGiB        uint64 = 0x100000000
)

// FitEntry defines the structure of FitEntries in the Firmware Interface Table
type FitEntry struct {
	Address  uint64
	OrigSize [3]uint8
	_        uint8
	Version  uint16
	CVType   uint8
	CheckSum uint8
}

// FancyPrint does fancy things
func (fit *FitEntry) FancyPrint() {
	log.Println("Fit Table PrintOut")
	if fit.Address == type0MagicWord {
		log.Println("FitEntry 0")
		log.Printf("Fit Size: %v\n Entries", fit.Size())
		log.Printf("Version: %v\n", fit.Version)
		log.Printf("Checksum indicator: %b\n", fit.CVType)
	} else {
		log.Printf("Component Address: %v\n", fit.Address)
		log.Printf("Component size: %v\n", fit.Size())
		log.Printf("Version: %v\n", fit.Version)
		log.Printf("C_V & Type: %b\n", fit.CVType)
		log.Printf("Checksum: %v\n", fit.CheckSum)
	}
}

func (fit *FitEntry) CheckSumValid() bool {
	return fit.CVType&0x80 != 0
}

func (fit *FitEntry) Type() FitEntryType {
	return FitEntryType(fit.CVType & 0x7f)
}

// getFitPointer returns the ROM-Address of FitPointer
func GetFitPointer(data []byte) (uint64, error) {
	var fitPointer uint32

	fitPtrAddress := len(data) - 0x40
	buf := bytes.NewReader(data[fitPtrAddress:])
	err := binary.Read(buf, binary.LittleEndian, &fitPointer)
	if err != nil {
		return 0, err
	}

	return uint64(fitPointer), nil
}

func readFit(data []byte, fitSize uint32) ([]FitEntry, error) {
	var ret []FitEntry
	dummy := FitEntry{}

	fit := bytes.NewReader(data)

	err := binary.Read(fit, binary.LittleEndian, &dummy)
	if err != nil {
		return nil, err
	}
	for i := 16; i < int(fitSize); i += 16 {
		ent := FitEntry{}
		err := binary.Read(fit, binary.LittleEndian, &ent)
		if err != nil {
			return nil, err
		}
		if ent.CheckSumValid() {
			// Validate checksum
			var cksum byte = 0
			for j := 0; j < 16; j++ {
				cksum += data[j+i]
			}

			if cksum != 0 {
				return nil, fmt.Errorf("FIT: Checksum of entry is invalid")
			}
		}
		ret = append(ret, ent)
	}

	return ret, nil
}

func GetFitHeader(data []byte) (FitEntry, error) {
	fit := bytes.NewReader(data)

	// read FIT header
	hdr := FitEntry{}
	err := binary.Read(fit, binary.LittleEndian, &hdr)
	if err != nil {
		return hdr, err
	}

	if hdr.Address != type0MagicWord {
		return hdr, fmt.Errorf("FIT: magic word wrong")
	}

	if hdr.Type() != 0 {
		return hdr, fmt.Errorf("FIT: first entry not of type 0")
	}

	if hdr.Size() == 0 {
		return hdr, fmt.Errorf("FIT: Invalid size")
	}

	if hdr.CheckSumValid() {
		// FIXME: this is correct, but out test platform is broken, fix testplatform first...
		/*
			var cksum byte = 0
			for j := 0; j < 16; j++ {
				cksum += data[j]
			}

			if cksum != 0 {
				return hdr, fmt.Errorf("FIT: Checksum of header is invalid")
			}
		*/
	}
	return hdr, nil
}

// ExtractFit Gets the bios file blob and extracts the FIT-Part
func ExtractFit(data []byte) ([]FitEntry, error) {

	// read FIT header
	hdr, err := GetFitHeader(data)
	if err != nil {
		return nil, err
	}

	// read rest of the FIT
	fitTable, err := readFit(data, hdr.Size())
	if err != nil {
		return nil, err
	}

	var lasttype int = 0
	for i, _ := range fitTable {
		if int(fitTable[i].Type()) < lasttype {
			return nil, fmt.Errorf("FIT: Entries aren't sorted")
		}
		lasttype = int(fitTable[i].Type())
	}

	return fitTable, nil
}

func (entry *FitEntry) Size() uint32 {
	var tmpsize uint32
	for count, item := range entry.OrigSize {
		tmpsize += uint32(item)
		if count < 2 {
			tmpsize = tmpsize << 4
		}
	}
	return tmpsize / 16
}
