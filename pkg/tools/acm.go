package tools

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"

	"github.com/google/go-tpm/tpm2"
)

const (
	//ACMChipsetTypeBios as defined in Document 315168-016 Chapter A.1 Table 8. Authenticated Code Module Format
	ACMChipsetTypeBios uint8 = 0x00
	//ACMChipsetTypeSinit as defined in Document 315168-016 Chapter A.1 Table 8. Authenticated Code Module Format
	ACMChipsetTypeSinit uint8 = 0x01
	//ACMChipsetTypeBiosRevoc as defined in Document 315168-016 Chapter A.1 Table 10. Chipset AC Module Information Table
	ACMChipsetTypeBiosRevoc uint8 = 0x08
	//ACMChipsetTypeSinitRevoc as defined in Document 315168-016 Chapter A.1 Table 10. Chipset AC Module Information Table
	ACMChipsetTypeSinitRevoc uint8 = 0x09
	//ACMTypeChipset as defined in Document 315168-016 Chapter A.1 Table 8. Authenticated Code Module Format
	ACMTypeChipset uint16 = 0x02
	//ACMSubTypeReset FIXME
	ACMSubTypeReset uint16 = 0x01
	//ACMVendorIntel as defined in Document 315168-016 Chapter A.1 Table 8. Authenticated Code Module Format
	ACMVendorIntel uint32 = 0x8086

	//TPMExtPolicyIllegal as defined in Document 315168-016 Chapter A.1 Table 16. TPM Capabilities Field
	TPMExtPolicyIllegal uint8 = 0x00
	//TPMExtPolicyAlgAgile as defined in Document 315168-016 Chapter A.1 Table 16. TPM Capabilities Field
	TPMExtPolicyAlgAgile uint8 = 0x01
	//TPMExtPolicyEmbeddedAlgs as defined in Document 315168-016 Chapter A.1 Table 16. TPM Capabilities Field
	TPMExtPolicyEmbeddedAlgs uint8 = 0x10
	//TPMExtPolicyBoth as defined in Document 315168-016 Chapter A.1 Table 16. TPM Capabilities Field
	TPMExtPolicyBoth uint8 = 0x11

	//TPMFamilyIllegal as defined in Document 315168-016 Chapter A.1 Table 16. TPM Capabilities Field
	TPMFamilyIllegal uint16 = 0x0000
	//TPMFamilyDTPM12 as defined in Document 315168-016 Chapter A.1 Table 16. TPM Capabilities Field
	TPMFamilyDTPM12 uint16 = 0x0001
	//TPMFamilyDTPM20 as defined in Document 315168-016 Chapter A.1 Table 16. TPM Capabilities Field
	TPMFamilyDTPM20 uint16 = 0x0010
	//TPMFamilyDTPMBoth combination out of TPMFamilyDTPM12 and TPMFamilyDTPM20
	TPMFamilyDTPMBoth uint16 = 0x0011
	//TPMFamilyPTT20 as defined in Document 315168-016 Chapter A.1 Table 16. TPM Capabilities Field
	TPMFamilyPTT20 uint16 = 0x1000

	//ACMUUIDV3 as defined in Document 315168-016 Chapter A.1 Table 10. Chipset AC Module Information Table
	ACMUUIDV3 string = "7fc03aaa-46a7-18db-ac2e-698f8d417f5a"
	//ACMSizeOffset as defined in Document 315168-016 Chapter A.1 Table 8. Authenticated Code Module Format
	ACMSizeOffset int64 = 24

	//ACMheaderLen as defined in Document 315168-016 Chapter A.1 Table 8. Authenticated Code Module Format (Version 0.0)
	ACMheaderLen uint32 = 161

	//ACMModuleSubtypeSinitACM is an enum
	ACMModuleSubtypeSinitACM uint16 = 0
	//ACMModuleSubtypeCapableOfExecuteAtReset is a flag and enum Based on EDK2 Silicon/Intel/Tools/FitGen/FitGen.c
	ACMModuleSubtypeCapableOfExecuteAtReset uint16 = 1
	//ACMModuleSubtypeAncModule is a flag Based on EDK2 Silicon/Intel/Tools/FitGen/FitGen.c
	ACMModuleSubtypeAncModule uint16 = 2
)

//UUID represents an UUID
type UUID struct {
	Field1 uint32
	Field2 uint16
	Field3 uint16
	Field4 uint16
	Field5 [6]uint8
}

// ACMInfo holds the metadata extracted from the ACM header
type ACMInfo struct {
	UUID                UUID
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

//ChipsetID describes the chipset ID found in the ACM header
type ChipsetID struct {
	Flags      uint32
	VendorID   uint16
	DeviceID   uint16
	RevisionID uint16
	Reserved   [3]uint16
}

//Chipsets hold a list of supported chipset IDs as found in the ACM header
type Chipsets struct {
	Count  uint32
	IDList []ChipsetID
}

//ProcessorID describes the processor ID found in the ACM header
type ProcessorID struct {
	FMS          uint32
	FMSMask      uint32
	PlatformID   uint64
	PlatformMask uint64
}

//Processors hold a list of supported processor IDs as found in the ACM header
type Processors struct {
	Count  uint32
	IDList []ProcessorID
}

// TPMs describes the required TPM capabilities and algorithm as found in the ACM header
type TPMs struct {
	Capabilities uint32
	Count        uint16
	AlgID        []tpm2.Algorithm
}

// ACMHeader exports the structure of ACM Header found in the firmware interface table
type ACMHeader struct {
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
	Signature       [256]uint8
}

// ACM exports the structure of Authenticated Code Modules found in the Firmware Interface Table(FIT)
type ACM struct {
	Header  ACMHeader
	Scratch []byte
	Info    ACMInfo
}

// ACMFlags exports the ACM header flags
type ACMFlags struct {
	Production    bool
	PreProduction bool
	DebugSigned   bool
}

// ParseACMHeader exports the functionality of parsing an ACM Header
func ParseACMHeader(data []byte) (*ACMHeader, error) {
	var acm ACMHeader
	buf := bytes.NewReader(data)
	err := binary.Read(buf, binary.LittleEndian, &acm)

	if err != nil {
		return nil, fmt.Errorf("Can't read ACM Header")
	}

	return &acm, nil
}

// ValidateACMHeader validates an ACM Header found in the Firmware Interface Table (FIT)
func ValidateACMHeader(acmheader *ACMHeader) (bool, error) {
	if acmheader.ModuleType != uint16(2) {
		return false, fmt.Errorf("BIOS ACM ModuleType is not 2, this is not specified")
	}
	// Early version of TXT used an enum in ModuleSubType
	// That was changed to flags. Check if unsupported flags are present
	if acmheader.ModuleSubType > (ACMModuleSubtypeAncModule | ACMModuleSubtypeCapableOfExecuteAtReset) {
		return false, fmt.Errorf("BIOS ACM ModuleSubType contains unknown flags")
	}
	if acmheader.HeaderLen < uint32(ACMheaderLen) {
		return false, fmt.Errorf("BIOS ACM HeaderLength is smaller than 4*161 Byte")
	}
	if acmheader.Size == 0 {
		return false, fmt.Errorf("BIOS ACM Size can't be zero")
	}
	if acmheader.ModuleVendor != ACMVendorIntel {
		return false, fmt.Errorf("AC Module Vendor is not Intel. Only Intel as Vendor is allowed")
	}
	if acmheader.KeySize*4 != uint32(len(acmheader.PubKey)) {
		return false, fmt.Errorf("ACM keysize of 0x%x not supported yet", acmheader.KeySize*4)
	}
	if acmheader.ScratchSize > acmheader.Size {
		return false, fmt.Errorf("ACM ScratchSize is bigger than ACM module size")
	}
	return true, nil
}

//ParseACM deconstructs a byte array containing the raw ACM into it's components
func ParseACM(data []byte) (*ACM, *Chipsets, *Processors, *TPMs, error, error) {
	var acmheader ACMHeader
	var acminfo ACMInfo
	var processors Processors
	var chipsets Chipsets
	var tpms TPMs

	buf := bytes.NewReader(data)
	err := binary.Read(buf, binary.LittleEndian, &acmheader)
	if err != nil {
		return nil, nil, nil, nil, nil, err
	}
	scratch := make([]byte, acmheader.ScratchSize*4)

	err = binary.Read(buf, binary.LittleEndian, &scratch)
	if err != nil {
		return nil, nil, nil, nil, nil, err
	}

	if (acmheader.ModuleSubType & ACMModuleSubtypeAncModule) > 0 {
		// ANC modules do not have an ACMINFO header
		acm := ACM{acmheader, scratch, acminfo}
		return &acm, &chipsets, &processors, &tpms, nil, nil
	}

	err = binary.Read(buf, binary.LittleEndian, &acminfo)
	if err != nil {
		return nil, nil, nil, nil, nil, err
	}

	acm := ACM{acmheader, scratch, acminfo}

	buf.Seek(int64(acm.Info.ChipsetIDList), io.SeekStart)
	err = binary.Read(buf, binary.LittleEndian, &chipsets.Count)
	if err != nil {
		return nil, nil, nil, nil, nil, err
	}

	chipsets.IDList = make([]ChipsetID, chipsets.Count)
	err = binary.Read(buf, binary.LittleEndian, &chipsets.IDList)
	if err != nil {
		return nil, nil, nil, nil, nil, err
	}

	buf.Seek(int64(acm.Info.ProcessorIDList), io.SeekStart)
	err = binary.Read(buf, binary.LittleEndian, &processors.Count)
	if err != nil {
		return nil, nil, nil, nil, nil, err
	}

	processors.IDList = make([]ProcessorID, processors.Count)
	err = binary.Read(buf, binary.LittleEndian, &processors.IDList)
	if err != nil {
		return nil, nil, nil, nil, nil, err
	}

	if acm.Info.ACMVersion >= 5 {
		buf.Seek(int64(acm.Info.TPMInfoList), io.SeekStart)
		err = binary.Read(buf, binary.LittleEndian, &tpms.Capabilities)
		if err != nil {
			return nil, nil, nil, nil, nil, err
		}

		err = binary.Read(buf, binary.LittleEndian, &tpms.Count)
		if err != nil {
			return nil, nil, nil, nil, nil, err
		}

		tpms.AlgID = make([]tpm2.Algorithm, tpms.Count)
		for i := 0; i < int(tpms.Count); i++ {
			err = binary.Read(buf, binary.LittleEndian, &tpms.AlgID[i])
			if err != nil {
				return nil, nil, nil, nil, nil, err
			}
		}
	}

	return &acm, &chipsets, &processors, &tpms, nil, nil
}

//LookupACMSize returns the ACM size
func LookupACMSize(header []byte) (int64, error) {
	var acmSize uint32

	buf := bytes.NewReader(header[:32])
	buf.Seek(ACMSizeOffset, io.SeekStart)
	err := binary.Read(buf, binary.LittleEndian, &acmSize)
	if err != nil {
		return 0, err
	}

	return int64(acmSize * 4), nil
}

// ParseACMFlags parses the ACM Header flags
func (a *ACMHeader) ParseACMFlags() *ACMFlags {
	var flags ACMFlags
	flags.Production = (a.Flags>>15)&1 == 0 && (a.Flags>>14)&1 == 0
	flags.PreProduction = (a.Flags>>14)&1 != 0
	flags.DebugSigned = (a.Flags>>15)&1 != 0
	return &flags
}

//PrettyPrint prints a human readable representation of the ACMHeader
func (a *ACMHeader) PrettyPrint() {
	fmt.Println("----Authenticated Code Module----")
	fmt.Println()
	if a.ModuleVendor == ACMVendorIntel {
		fmt.Println("   Module Vendor: Intel")
	} else {
		fmt.Println("   Module Vendor: Unknown")
	}

	if a.ModuleType == ACMTypeChipset {
		fmt.Println("   Module Type: ACM_TYPE_CHIPSET")
	} else {
		fmt.Println("   Module Type: UNKNOWN")
	}

	if a.ModuleSubType == ACMSubTypeReset {
		fmt.Println("   Module Subtype: Execute at Reset")
	} else if a.ModuleSubType == 0 {
		fmt.Println("   Module Subtype: 0x0")
	} else {
		fmt.Println("   Module Subtype: Unknown")
	}
	fmt.Printf("   Module Date: 0x%02x\n", a.Date)
	fmt.Printf("   Module Size: 0x%x (%d)\n", a.Size*4, a.Size*4)

	fmt.Printf("   Header Length: 0x%x (%d)\n", a.HeaderLen, a.HeaderLen)
	fmt.Printf("   Header Version: %d\n", a.HeaderVersion)
	fmt.Printf("   Chipset ID: 0x%02x\n", a.ChipsetID)
	fmt.Printf("   Flags: 0x%02x\n", a.Flags)
	fmt.Printf("   TXT SVN: 0x%08x\n", a.TxtSVN)
	fmt.Printf("   SE SVN: 0x%08x\n", a.SeSVN)
	fmt.Printf("   Code Control: 0x%02x\n", a.CodeControl)
	fmt.Printf("   Entry Point: 0x%08x:%08x\n", a.SegSel, a.EntryPoint)
	fmt.Printf("   Scratch Size: 0x%x (%d)\n", a.ScratchSize, a.ScratchSize)
}

//PrettyPrint prints a human readable representation of the ACM
func (a *ACM) PrettyPrint() {
	a.Header.PrettyPrint()
	fmt.Println("   --Info Table--")

	uuidStr := fmt.Sprintf("%08x-%04x-%04x-%04x-%02x%02x%02x%02x%02x%02x",
		a.Info.UUID.Field1,
		a.Info.UUID.Field2,
		a.Info.UUID.Field3,
		a.Info.UUID.Field4,
		a.Info.UUID.Field5[0],
		a.Info.UUID.Field5[1],
		a.Info.UUID.Field5[2],
		a.Info.UUID.Field5[3],
		a.Info.UUID.Field5[4],
		a.Info.UUID.Field5[5])

	if uuidStr == ACMUUIDV3 {
		fmt.Println("      UUID: ACM_UUID_V3")
	}

	switch a.Info.ChipsetACMType {
	case ACMChipsetTypeBios:
		fmt.Println("      Chipset ACM: BIOS")
		break
	case ACMChipsetTypeBiosRevoc:
		fmt.Println("      Chipset ACM: BIOS Revocation")
		break
	case ACMChipsetTypeSinit:
		fmt.Println("      Chipset ACM: SINIT")
		break
	case ACMChipsetTypeSinitRevoc:
		fmt.Println("      Chipset ACM: SINIT Revocation")
		break
	default:
		fmt.Println("      Chipset ACM: Unknown")
	}

	fmt.Printf("      Version: %d\n", a.Info.Version)
	fmt.Printf("      Length: 0x%x (%d)\n", a.Info.Length, a.Info.Length)
	fmt.Printf("      Chipset ID List: 0x%02x\n", a.Info.ChipsetIDList)
	fmt.Printf("      OS SINIT Data Version: 0x%02x\n", a.Info.OSSinitDataVersion)
	fmt.Printf("      Min. MLE Header Version: 0x%08x\n", a.Info.MinMleHeaderVersion)
	fmt.Printf("      Capabilities: 0x%08x\n", a.Info.TxtCaps)
	fmt.Printf("      ACM Version: %d\n", a.Info.ACMVersion)
}

//PrettyPrint prints a human readable representation of the Chipsets
func (c *Chipsets) PrettyPrint() {
	fmt.Println("   --Chipset List--")
	fmt.Printf("      Entries: %d\n", c.Count)
	for idx, chipset := range c.IDList {
		fmt.Printf("      Entry %d:\n", idx)
		fmt.Printf("         Flags: 0x%02x\n", chipset.Flags)
		fmt.Printf("         Vendor: 0x%02x\n", chipset.VendorID)
		fmt.Printf("         Device: 0x%02x\n", chipset.DeviceID)
		fmt.Printf("         Revision: 0x%02x\n", chipset.RevisionID)
	}
}

//PrettyPrint prints a human readable representation of the Processors
func (p *Processors) PrettyPrint() {
	fmt.Println("   --Processor List--")
	fmt.Printf("      Entries: %d\n", p.Count)
	for idx, processor := range p.IDList {
		fmt.Printf("      Entry %d:\n", idx)
		fmt.Printf("         FMS: 0x%02x\n", processor.FMS)
		fmt.Printf("         FMS Maks: 0x%02x\n", processor.FMSMask)
		fmt.Printf("         Platform ID: 0x%02x\n", processor.PlatformID)
		fmt.Printf("         Platform Mask: 0x%02x\n", processor.PlatformMask)
	}
}

//PrettyPrint prints a human readable representation of the TPMs
func (t *TPMs) PrettyPrint() {
	fmt.Println("   --TPM Info List--")
	fmt.Println("      Capabilities:")
	fmt.Printf("         External Policy: %02x\n", t.Capabilities)
	fmt.Printf("      Algorithms: %d\n", t.Count)
	for _, algo := range t.AlgID {
		fmt.Printf("         %v\n", algo.String())
	}
}
