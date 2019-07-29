package api

import (
	"fmt"
	"io"
	"bytes"
	"encoding/binary"
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
	fitPointer     int64  = 0xFFFFFFC0
	type0MagicWord uint64 = 0x2020205f5449465f
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

func readFit(fit io.Reader, fitSize uint32) ([]FitEntry, error) {
	var ret []FitEntry

	for i := uint32(16); i < fitSize; i+=16{
		ent := FitEntry{}
		err := binary.Read(fit, binary.LittleEndian, &ent)
		if err != nil {
			return nil, err
		}

		ret = append(ret, ent)
	}

	return ret, nil
}

// ExtractFit Gets the bios file blob and extracts the FIT-Part
func ExtractFit(data []byte) ([]FitEntry, error) {
	// get FIT pointer
	fitPointer, err := GetFitPointer(data)
	if err != nil {
		return nil, err
	}

	// follow FIT pointer to FIT
	fitAddress := (fitPointer - 0x100000000) + uint64(len(data))
	fit := bytes.NewReader(data[fitAddress:])

	// read FIT header
	hdr := FitEntry{}
	err = binary.Read(fit, binary.LittleEndian, &hdr)
	if err != nil {
		return nil, err
	}

	if hdr.Address != type0MagicWord {
		return nil, fmt.Errorf("No FIT: magic word wrong")
	}

	if hdr.Type() != 0 {
	return nil, fmt.Errorf("No FIT: first entry not of type 0")
	}

	// read rest of the FIT
	fitTable, err := readFit(fit, hdr.Size())
	if err != nil {
		return nil, err
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
