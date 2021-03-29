package tools

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"log"
)

// For reference check Document 599500 "Firmware Interface Table"

// FitEntryType the type of FIT entry inside the FIT table
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
	// FourGiB is a constant representing 4GiB
	FourGiB uint64 = 0x100000000
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
		log.Printf("Fit Size: 0x%x\n Entries", fit.Size())
		log.Printf("Version: 0x%x\n", fit.Version)
		log.Printf("Checksum indicator: 0x%x\n", fit.CVType)
	} else {
		log.Printf("Component Address: 0x%x\n", fit.Address)
		log.Printf("Component size: 0x%x\n", fit.Size())
		log.Printf("Version: 0x%x\n", fit.Version)
		log.Printf("C_V & Type: 0x%x\n", fit.CVType)
		log.Printf("Checksum: 0x%x\n", fit.CheckSum)
	}
}

//CheckSumValid returns true when the fit entry checksum valid bit is set
func (fit *FitEntry) CheckSumValid() bool {
	return fit.CVType&0x80 != 0
}

//Type returns the fit entry type
func (fit *FitEntry) Type() FitEntryType {
	return FitEntryType(fit.CVType & 0x7f)
}

// GetFitPointer returns the ROM-Address of FitPointer
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

func readFit(reader io.Reader, fitSize uint32, data []byte) ([]FitEntry, error) {
	var ret []FitEntry
	for i := 16; i < int(fitSize); i += 16 {
		ent := FitEntry{}
		err := binary.Read(reader, binary.LittleEndian, &ent)
		if err != nil {
			return nil, err
		}
		if ent.Type() == UnusedEntry {
			continue
		}
		// Intel's Firmware Interface Table Bios Specification
		// recommends to clear CheckSumValid bit on all entries
		if ent.CheckSumValid() {
			// Validate checksum
			var cksum byte
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

//GetFitHeader extracts the fit header from raw data
func GetFitHeader(reader io.Reader) (FitEntry, error) {
	// read FIT header
	hdr := FitEntry{}
	var err error
	for {
		err = binary.Read(reader, binary.LittleEndian, &hdr)
		if err != nil {
			break
		}
		if hdr.Address == type0MagicWord && hdr.Type() == FitHeader && hdr.Size() != 0 {
			return hdr, nil
		}
	}
	return FitEntry{}, err
}

// ExtractFit extracts all entries from the fit and checks the checksum
func ExtractFit(data []byte) ([]FitEntry, error) {
	fit := bytes.NewReader(data)
	// read FIT header
	hdr, err := GetFitHeader(fit)
	if err != nil {
		return nil, err
	}
	// read rest of the FIT
	fitTable, err := readFit(fit, hdr.Size(), data)
	if err != nil {
		return nil, err
	}

	var completeFit []FitEntry
	completeFit = append(completeFit, hdr)
	completeFit = append(completeFit, fitTable...)

	// Intel's Firmware Interface Table Bios Specification recommends
	// to set CheckSumValid in the header.
	// Need to verify the whole table in that case, not only the header
	if hdr.CheckSumValid() {
		var cksum byte
		buf := new(bytes.Buffer)
		err := binary.Write(buf, binary.BigEndian, completeFit)
		if err != nil {
			return nil, fmt.Errorf("FIT: Unable to parse FIT Entries: %v", err)
		}
		bufSlice := buf.Bytes()

		for j := 0; j < int(hdr.Size()); j++ {
			cksum += bufSlice[j]
		}

		if cksum != 0 {
			return nil, fmt.Errorf("FIT: Checksum of FIT is invalid")
		}
	}
	var lasttype int
	for i := range fitTable {
		if fitTable[i].Type() == UnusedEntry {
			/*
			 * Specification: Firmware Interface Table Document 599500
			 * Chapter "4.0 Firmware Interface Table"
			 *
			 * The FIT processing code always skips the unused entry and moves on to the next record.
			 */
			continue
		}
		if int(fitTable[i].Type()) < lasttype {
			return nil, fmt.Errorf("FIT: Entries aren't sorted - See: Firmware Interface Table - BIOS Specification, Document: 338505-001, P.8")
		}
		lasttype = int(fitTable[i].Type())
	}

	return fitTable, nil
}

//Size returns the size in bytes of the entry
func (fit *FitEntry) Size() uint32 {

	var tmpsize uint32

	if fit.Type() == FitHeader || fit.Type() == BIOSStartUpMod {
		for count, item := range fit.OrigSize {
			tmpsize += uint32(item)
			if count < 2 {
				tmpsize = tmpsize << 4
			}
		}
		return tmpsize / 16
	}

	buf := bytes.NewBuffer(append(fit.OrigSize[:], 0))
	err := binary.Read(buf, binary.LittleEndian, &tmpsize)
	if err != nil {
		fmt.Printf("Error getting Fit Entry Size: %v\n", err)
		return 0
	}
	return tmpsize
}
