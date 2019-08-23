package api

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"log"
)

const (
	ACMChipsetTypeBios       uint8  = 0x00
	ACMChipsetTypeSinit      uint8  = 0x01
	ACMChipsetTypeBiosRevoc  uint8  = 0x08
	ACMChipsetTypeSinitRevoc uint8  = 0x09
	ACMTypeChipset           uint16 = 0x02
	ACMSubTypeReset          uint16 = 0x01
	ACMVendorIntel           uint32 = 0x8086
	TPMExtPolicyIllegal      uint8  = 0x00
	TPMExtPolicyAlgAgile     uint8  = 0x01
	TPMExtPolicyEmbeddedAlgs uint8  = 0x10
	TPMExtPolicyBoth         uint8  = 0x11
	TPMFamilyIllegal         uint16 = 0x0000
	TPMFamilyDTPM12          uint16 = 0x0001
	TPMFamilyDTPM20          uint16 = 0x0010
	TPMFamilyDTPMBoth        uint16 = 0x0011
	TPMFamilyPTT20           uint16 = 0x1000
	ACMUUIDV3                string = "7fc03aaa-46a7-18db-ac2e-698f8d417f5a"
	ACMSizeOffset            int64  = 24
	TPMAlgoSHA1              uint16 = 0x0004
	TPMAlgoSHA256            uint16 = 0x000b
	TPMAlgoSHA384            uint16 = 0x000c
	TPMAlgoSHA512            uint16 = 0x000d
	TPMAlgoNULL              uint16 = 0x0010
	TPMAlgoSM3_256           uint16 = 0x0012
	TPMAlgoRSASSA            uint16 = 0x0014
	TPMAlgoECDSA             uint16 = 0x0018
	TPMAlgoSM2               uint16 = 0x001B
)

type UUID struct {
	Field1 uint32
	Field2 uint16
	Field3 uint16
	Field4 uint16
	Field5 [6]uint8
}

type ACMInfo struct {
	Uuid                UUID
	ChipsetACMType      uint8
	Version             uint8
	Length              uint16
	ChipsetIDList       uint32
	OSSinitDataVersion  uint32
	MinMleHeaderVersion uint32
	TxtCaps             uint32
	ACMVersion          uint8
	Reserved            [3]uint8
	ProcessorIDList     uint32
	TPMInfoList         uint32
}

type ChipsetID struct {
	Flags      uint32
	VendorID   uint16
	DeviceID   uint16
	RevisionID uint16
	Reserved   uint16
	ExtendedID uint16
}

type Chipsets struct {
	Count  uint32
	IDList []ChipsetID
}

type ProcessorID struct {
	FMS          uint32
	FMSMask      uint32
	PlatformID   uint64
	PlatformMask uint64
}

type Processors struct {
	Count  uint32
	IDList []ProcessorID
}

type TPMs struct {
	Capabilities uint32
	Count        uint16
	AlgID        []uint16
}

type ACM struct {
	ModuleType      uint16
	ModuleSubType   uint16
	HeaderLen       uint32
	HeaderVersion   uint32
	ChipsetID       uint16
	Flags           uint16
	ModuleVendor    uint32
	Date            uint32
	Size            uint32
	TxtSVN          uint16
	SeSVN           uint16
	CodeControl     uint32
	ErrorEntryPoint uint32
	GDTLimit        uint32
	GDTBase         uint32
	SegSel          uint32
	EntryPoint      uint32
	Reserved2       [64]uint8
	KeySize         uint32
	ScratchSize     uint32
	PubKey          [256]uint8
	PubExp          uint32
	Signatur        [256]uint8
	Scratch         [143]uint32
	Info            ACMInfo
}

// ParseACMHeader

func ParseACMHeader(data []byte) (*ACM, error) {
	var acm ACM
	buf := bytes.NewReader(data)
	err := binary.Read(buf, binary.LittleEndian, &acm)

	if err != nil {
		return nil, fmt.Errorf("Can't read ACM Header")
	}

	return &acm, nil
}

// ValidateACMHeader
func ValidateACMHeader(acm *ACM) (bool, error) {
	if acm.ModuleType != uint16(2) {
		return false, fmt.Errorf("BIOS ACM ModuleType is not 2, this is not specified - Intel TXT Software Development Guide, Document: 315168-013, P. 84")
	}
	if acm.ModuleSubType >= uint16(2) {
		return false, fmt.Errorf("BIOS ACM ModuleSubType is greater 1, this is not specified - Intel TXT Software Development Guide, Document: 315168-013, P. 84")
	}
	if acm.HeaderLen < uint32(4*161) {
		return false, fmt.Errorf("BIOS ACM HeaderLength is smaller than 4*161 Byte - Intel TXT Software Development Guide, Document: 315168-013, P. 83")
	}
	if acm.Size == 0 {
		return false, fmt.Errorf("BIOS ACM Size can't be zero!")
	}
	return true, nil
}

// ParseACM
func ParseACM(data []byte) (*ACM, *Chipsets, *Processors, *TPMs, error) {
	var acm ACM
	var processors Processors
	var chipsets Chipsets
	var tpms TPMs

	buf := bytes.NewReader(data)
	err := binary.Read(buf, binary.LittleEndian, &acm)
	if err != nil {
		return nil, nil, nil, nil, err
	}

	buf.Seek(int64(acm.Info.ChipsetIDList), io.SeekStart)
	err = binary.Read(buf, binary.LittleEndian, &chipsets.Count)
	if err != nil {
		return nil, nil, nil, nil, err
	}

	chipsets.IDList = make([]ChipsetID, chipsets.Count)
	err = binary.Read(buf, binary.LittleEndian, &chipsets.IDList)
	if err != nil {
		return nil, nil, nil, nil, err
	}

	buf.Seek(int64(acm.Info.ProcessorIDList), io.SeekStart)
	err = binary.Read(buf, binary.LittleEndian, &processors.Count)
	if err != nil {
		return nil, nil, nil, nil, err
	}

	processors.IDList = make([]ProcessorID, processors.Count)
	err = binary.Read(buf, binary.LittleEndian, &processors.IDList)
	if err != nil {
		return nil, nil, nil, nil, err
	}

	buf.Seek(int64(acm.Info.TPMInfoList), io.SeekStart)
	err = binary.Read(buf, binary.LittleEndian, &tpms.Capabilities)
	if err != nil {
		return nil, nil, nil, nil, err
	}

	err = binary.Read(buf, binary.LittleEndian, &tpms.Count)
	if err != nil {
		return nil, nil, nil, nil, err
	}

	tpms.AlgID = make([]uint16, tpms.Count)
	for i := 0; i < int(tpms.Count); i++ {
		err = binary.Read(buf, binary.LittleEndian, &tpms.AlgID[i])
		if err != nil {
			return nil, nil, nil, nil, err
		}
	}

	return &acm, &chipsets, &processors, &tpms, nil
}

func LookupSize(header []byte) (int64, error) {
	var acmSize uint32

	buf := bytes.NewReader(header[:32])
	buf.Seek(ACMSizeOffset, io.SeekStart)
	err := binary.Read(buf, binary.LittleEndian, &acmSize)
	if err != nil {
		return 0, err
	}

	return int64(acmSize * 4), nil
}

func (a *ACM) PrettyPrint() {
	log.Println("Authenticated Code Module")

	if a.ModuleVendor == ACMVendorIntel {
		log.Println("Module Vendor: Intel")
	} else {
		log.Println("Module Vendor: Unknown")
	}

	if a.ModuleType == ACMTypeChipset {
		log.Println("Module Type: ACM_TYPE_CHIPSET")
	} else {
		log.Println("Module Type: UNKNOWN")
	}

	if a.ModuleSubType == ACMSubTypeReset {
		log.Println("Module Subtype: Execute at Reset")
	} else if a.ModuleSubType == 0 {
		log.Println("Module Subtype: 0x0")
	} else {
		log.Println("Module Subtype: Unknown")
	}
	log.Printf("Module Date: 0x%02x\n", a.Date)
	log.Printf("Module Size: %db\n", a.Size*4)

	log.Printf("Header Length: %db\n", a.HeaderLen)
	log.Printf("Header Version: %d\n", a.HeaderVersion)
	log.Printf("Chipset ID: 0x%02x\n", a.ChipsetID)
	log.Printf("Flags: 0x%02x\n", a.Flags)
	log.Printf("TXT SVN: 0x%08x\n", a.TxtSVN)
	log.Printf("SE SVN: 0x%08x\n", a.SeSVN)
	log.Printf("Code Control: 0x%02x\n", a.CodeControl)
	log.Printf("Entry Point: 0x%08x:%08x\n", a.SegSel, a.EntryPoint)
	log.Printf("Scratch Size: %db\n", a.ScratchSize)
	log.Println("Info Table:")

	uuidStr := fmt.Sprintf("%08x-%04x-%04x-%04x-%02x%02x%02x%02x%02x%02x",
		a.Info.Uuid.Field1,
		a.Info.Uuid.Field2,
		a.Info.Uuid.Field3,
		a.Info.Uuid.Field4,
		a.Info.Uuid.Field5[0],
		a.Info.Uuid.Field5[1],
		a.Info.Uuid.Field5[2],
		a.Info.Uuid.Field5[3],
		a.Info.Uuid.Field5[4],
		a.Info.Uuid.Field5[5])

	if uuidStr == ACMUUIDV3 {
		log.Println("\tUUID: ACM_UUID_V3")
	}

	switch a.Info.ChipsetACMType {
	case ACMChipsetTypeBios:
		log.Println("\tChipset ACM: BIOS")
		break
	case ACMChipsetTypeBiosRevoc:
		log.Println("\tChipset ACM: BIOS Revocation")
		break
	case ACMChipsetTypeSinit:
		log.Println("\tChipset ACM: SINIT")
		break
	case ACMChipsetTypeSinitRevoc:
		log.Println("\tChipset ACM: SINIT Revocation")
		break
	default:
		log.Println("\tChipset ACM: Unknown")
	}

	log.Printf("\tVersion: %d\n", a.Info.Version)
	log.Printf("\tLength: %db\n", a.Info.Length)
	log.Printf("\tChipset ID List: 0x%02x\n", a.Info.ChipsetIDList)
	log.Printf("\tOS SINIT Data Version: 0x%02x\n", a.Info.OSSinitDataVersion)
	log.Printf("\tMin. MLE Header Version: 0x%08x\n", a.Info.MinMleHeaderVersion)
	log.Printf("\tCapabilities: 0x%08x\n", a.Info.TxtCaps)
	log.Printf("\tACM Version: %d\n", a.Info.ACMVersion)
}

func (c *Chipsets) PrettyPrint() {
	log.Println("Chipset List:")
	log.Printf("\tEntries: %d\n", c.Count)
	for idx, chipset := range c.IDList {
		log.Printf("\tEntry %d:\n", idx)
		log.Printf("\t\tFlags: 0x%02x\n", chipset.Flags)
		log.Printf("\t\tVendor: 0x%02x\n", chipset.VendorID)
		log.Printf("\t\tDevice: 0x%02x\n", chipset.DeviceID)
		log.Printf("\t\tRevision: 0x%02x\n", chipset.RevisionID)
		log.Printf("\t\tExtended: 0x%02x\n", chipset.ExtendedID)
	}
}

func (p *Processors) PrettyPrint() {
	log.Println("Processor List:")
	log.Printf("\tEntries: %d\n", p.Count)
	for idx, processor := range p.IDList {
		log.Printf("\tEntry %d:\n", idx)
		log.Printf("\t\tFMS: 0x%02x\n", processor.FMS)
		log.Printf("\t\tFMS Maks: 0x%02x\n", processor.FMSMask)
		log.Printf("\t\tPlatform ID: 0x%02x\n", processor.PlatformID)
		log.Printf("\t\tPlatform Mask: 0x%02x\n", processor.PlatformMask)
	}
}
func (t *TPMs) PrettyPrint() {
	log.Println("TPM Info List:")
	log.Println("\tCapabilities:")
	log.Printf("\t\tExternal Policy: %02x\n", t.Capabilities)
	log.Printf("\tAlgorithms: %d\n", t.Count)
	for _, algo := range t.AlgID {
		switch algo {
		case TPMAlgoNULL:
			log.Println("\t\tNULL")
			break
		case TPMAlgoSHA1:
			log.Println("\t\tSHA-1")
			break
		case TPMAlgoSHA256:
			log.Println("\t\tSHA-256")
			break
		case TPMAlgoSHA384:
			log.Println("\t\tSHA-384")
			break
		case TPMAlgoSHA512:
			log.Println("\t\tSHA-512")
			break
		case TPMAlgoSM3_256:
			log.Println("\t\tSM3-256")
			break
		case TPMAlgoRSASSA:
			log.Println("\t\tRSA-SSA")
			break
		case TPMAlgoECDSA:
			log.Println("\t\tEC-DSA")
			break
		case TPMAlgoSM2:
			log.Println("\t\tSM2")
			break
		default:
			log.Println("\t\tUnknown")
		}
	}
}
