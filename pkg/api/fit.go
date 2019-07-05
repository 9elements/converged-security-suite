package api

import (
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
	type0MagicWord uint64 = 0x5F4649545F202020
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
func getFitPointer(data []byte) ([]byte, error) {
	fitAddress := len(data) - 0x40
	var fitPointer [16]byte

	buf := bytes.NewReader(data)
	buf.ReadAt(fitPointer[:], int64(fitAddress))
	var fitPointerTMP []byte
	for _, item := range fitPointer {
		fitPointerTMP = append(fitPointerTMP, item)
	}
	return fitPointerTMP, nil
}

// convToRomAddress converts RAM-Address in FitPointer in RomAddress
func convToROMAddress(data []byte, fitPointer []byte) (int64, error) {
	buf := bytes.NewReader(fitPointer)
	var fitType0inRAMAddress int64
	err := binary.Read(buf, binary.LittleEndian, &fitType0inRAMAddress)
	if err != nil {
		return 0, err
	}
	var fitAddressinROMAddress = (fitType0inRAMAddress - 0x100000000) + int64(len(data))
	return fitAddressinROMAddress, nil
}

func readFit(data []byte, fitsize uint32, fitromaddress int64) ([]FitEntry, error) {
	fitTableBytes := make([]byte, fitsize*16)
	buf := bytes.NewReader(data)
	buf.ReadAt(fitTableBytes[:], fitromaddress)
	var fitTable []FitEntry
	buf = bytes.NewReader(fitTableBytes)
	err := binary.Read(buf, binary.LittleEndian, &fitTable)
	if err != nil {
		return nil, err
	}

	return fitTable, nil
}

// ExtractFit Gets the bios file blob and extracts the FIT-Part
func ExtractFit(data []byte) ([]FitEntry, error) {
	fitPointer, err := getFitPointer(data)
	if err != nil {
		return nil, err
	}

	fitRomAddress, err := convToROMAddress(data, fitPointer)
	if err != nil {
		return nil, err
	}
	// Read in 16 byte chunk at given address of file to get type0 Entry!!!
	var Entry0Bytes [16]byte
	buf := bytes.NewReader(data)
	buf.ReadAt(Entry0Bytes[:], fitRomAddress)
	//Convert again
	var type0EntryTMP []byte
	for _, item := range Entry0Bytes {
		type0EntryTMP = append(type0EntryTMP, item)
	}
	// Decode the actual Entry0
	var type0Entry FitEntry
	buf = bytes.NewReader(type0EntryTMP)
	err = binary.Read(buf, binary.BigEndian, &type0Entry)

	fitSize := type0Entry.Size()

	fitTable, err := readFit(data, fitSize, fitRomAddress)
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
