package api

import (
	"bytes"
	"encoding/binary"
	"golang.org/x/exp/mmap"
)

type fitEntryType uint16

// FitEntryTypes for distiction of Entries
const (
	FitHeader           fitEntryType = 0x00
	MCUpdate            fitEntryType = 0x01
	StartUpACMod        fitEntryType = 0x02
	BIOSStartUpMod      fitEntryType = 0x07
	TPMPolicyRec        fitEntryType = 0x08
	BIOSPolicyRec       fitEntryType = 0x09
	TXTPolicyRec        fitEntryType = 0x0A
	KeyManifestRec      fitEntryType = 0x0B
	BootPolicyManifest  fitEntryType = 0x0C
	CSESecBoot          fitEntryType = 0x10
	FeaturePolicyDelRec fitEntryType = 0x2D
	JumpDebugPol        fitEntryType = 0x2F
	UnusedEntry         fitEntryType = 0x7F
	// 0x03 - 0x06 	: Intel reserved
	// 0x0D - 0x0D 	: Intel reserved
	// 0x11 - 0x2C 	: Intel reserved
	// 0x2E 		: Intel reserved
	// 0x30 - 0x70	: Reserved for Manufacturer Use
	// 0x71 - 0x7E	: IntelReserved
)

// FitEntry defines the structure of FitEntries in the Firmware Interface Table
type FitEntry struct {
	Address  uint64
	Size     [3]uint8
	_        uint8
	Version  uint16
	CVType   uint8
	CheckSum uint8
}

const (
	fitPointer     int64 = 0xFFFFFFC0
	type0MagicWord int64 = 0x5F4649545F202020
)

// getFitPointer returns the ROM-Address of FitPointer
func getFitPointer(path string) ([]byte, error) {
	file, err := mmap.Open(path)
	if err != nil {
		return nil, err
	}
	fitAddress := file.Len() - 0x40
	var fitPointer [16]byte
	file.ReadAt(fitPointer[:], int64(fitAddress))
	var fitPointerTMP []byte
	for _, item := range fitPointer {
		fitPointerTMP = append(fitPointerTMP, item)
	}
	file.Close()
	return fitPointerTMP, nil
}

// convToRomAddress converts RAM-Address in FitPointer in RomAddress
func convToROMAddress(path string, fitPointer []byte) (int64, error) {
	file, err := mmap.Open(path)
	if err != nil {
		return 0, err
	}
	buf := bytes.NewReader(fitPointer)
	var fitType0inRAMAddress int64
	err = binary.Read(buf, binary.LittleEndian, &fitType0inRAMAddress)

	var fitAddressinROMAddress = (fitType0inRAMAddress - 0x100000000) + int64(file.Len())
	file.Close()
	return fitAddressinROMAddress, nil
}

func readFit(path string, fitsize uint32, fitromaddress int64) ([]FitEntry, error) {
	file, err := mmap.Open(path)
	if err != nil {
		return nil, err
	}
	fitTableBytes := make([]byte, fitsize*16)
	file.ReadAt(fitTableBytes[:], fitromaddress)
	var fitTable []FitEntry
	buf := bytes.NewReader(fitTableBytes)
	err = binary.Read(buf, binary.LittleEndian, &fitTable)
	if err != nil {
		return nil, err
	}

	return fitTable, nil
}

// ExtractFit Gets the bios file blob and extracts the FIT-Part
func ExtractFit(path string) ([]FitEntry, error) {
	fitPointer, err := getFitPointer(path)
	if err != nil {
		return nil, err
	}

	fitRomAddress, err := convToROMAddress(path, fitPointer)
	if err != nil {
		return nil, err
	}
	// Read in 16 byte chunk at given address of file to get type0 Entry!!!
	var Entry0Bytes [16]byte
	file, err := mmap.Open(path)
	file.ReadAt(Entry0Bytes[:], fitRomAddress)
	file.Close()
	//Convert again
	var type0EntryTMP []byte
	for _, item := range Entry0Bytes {
		type0EntryTMP = append(type0EntryTMP, item)
	}
	// Decode the actual Entry0
	var type0Entry FitEntry
	buf := bytes.NewReader(type0EntryTMP)
	err = binary.Read(buf, binary.BigEndian, &type0Entry)

	fitSize := getFitSize(type0Entry)

	fitTable, err := readFit(path, fitSize, fitRomAddress)
	if err != nil {
		return nil, err
	}
	return fitTable, nil

}

func getFitSize(entry FitEntry) uint32 {
	var tmpsize uint32
	for count, item := range entry.Size {
		tmpsize += uint32(item)
		if count < 2 {
			tmpsize = tmpsize << 4
		}
	}
	return tmpsize / 16
}

// ParseFit gets a byte-blop of data and searches for the FIT, extracts and returns it
func ParseFit(data []byte) ([]FitEntry, error) {

	return nil, nil

}
