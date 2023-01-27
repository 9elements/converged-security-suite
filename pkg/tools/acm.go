package tools

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"

	"github.com/google/go-tpm/tpm2"
	"github.com/linuxboot/fiano/pkg/intel/metadata/fit"
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
	ACMTypeChipset fit.ACModuleType = 0x02
	//ACMSubTypeReset FIXME
	ACMSubTypeReset uint16 = 0x01
	//ACMVendorIntel as defined in Document 315168-016 Chapter A.1 Table 8. Authenticated Code Module Format
	ACMVendorIntel fit.ACModuleVendor = 0x8086

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
	ACMModuleSubtypeSinitACM fit.ACModuleSubType = 0
	//ACMModuleSubtypeCapableOfExecuteAtReset is a flag and enum Based on EDK2 Silicon/Intel/Tools/FitGen/FitGen.c
	ACMModuleSubtypeCapableOfExecuteAtReset fit.ACModuleSubType = 1
	//ACMModuleSubtypeAncModule is a flag Based on EDK2 Silicon/Intel/Tools/FitGen/FitGen.c
	ACMModuleSubtypeAncModule fit.ACModuleSubType = 2
)

// UUID represents an UUID
type UUID struct {
	Field1 uint32
	Field2 uint16
	Field3 uint16
	Field4 uint16
	Field5 [6]uint8
}

// ACMRevision is the version of the ACM module in format <major>.<minor>.<build>
type ACMRevision [3]uint8

// String implements fmt.Stringer
func (r ACMRevision) String() string {
	return fmt.Sprintf("%d.%d.%d", r[0], r[1], r[2])
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
	ACMRevision         ACMRevision
	ProcessorIDList     uint32
	TPMInfoList         uint32
}

// ChipsetID describes the chipset ID found in the ACM header
type ChipsetID struct {
	Flags      uint32
	VendorID   uint16
	DeviceID   uint16
	RevisionID uint16
	Reserved   [3]uint16
}

// Chipsets hold a list of supported chipset IDs as found in the ACM header
type Chipsets struct {
	Count  uint32
	IDList []ChipsetID
}

// ProcessorID describes the processor ID found in the ACM header
type ProcessorID struct {
	FMS          uint32
	FMSMask      uint32
	PlatformID   uint64
	PlatformMask uint64
}

// Processors hold a list of supported processor IDs as found in the ACM header
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

// ACMFlags exports the ACM header flags
type ACMFlags struct {
	Production    bool
	PreProduction bool
	DebugSigned   bool
}

type ACM struct {
	Header     *fit.EntrySACMData
	Info       ACMInfo
	Chipsets   Chipsets
	Processors Processors
	TPMs       TPMs
}

// ValidateACMHeader validates an ACM Header found in the Firmware Interface Table (FIT)
func (a *ACM) ValidateACMHeader() (bool, error) {
	if uint16(a.Header.GetModuleType()) != uint16(2) {
		return false, fmt.Errorf("BIOS ACM ModuleType is not 2, this is not specified")
	}
	// Early version of TXT used an enum in ModuleSubType
	// That was changed to flags. Check if unsupported flags are present
	if a.Header.GetModuleSubType() > (ACMModuleSubtypeAncModule | ACMModuleSubtypeCapableOfExecuteAtReset) {
		return false, fmt.Errorf("BIOS ACM ModuleSubType contains unknown flags")
	}
	if uint32(a.Header.GetHeaderLen()) < uint32(ACMheaderLen) {
		return false, fmt.Errorf("BIOS ACM HeaderLength is smaller than 4*161 Byte")
	}
	if a.Header.GetSize() == 0 {
		return false, fmt.Errorf("BIOS ACM Size can't be zero")
	}
	if a.Header.GetModuleVendor() != ACMVendorIntel {
		return false, fmt.Errorf("AC Module Vendor is not Intel. Only Intel as Vendor is allowed")
	}
	if a.Header.GetScratchSize() > a.Header.GetSize() {
		return false, fmt.Errorf("ACM ScratchSize is bigger than ACM module size")
	}
	return true, nil
}

func (a *ACM) ParseACMInfo() error {
	userArea := bytes.NewReader(a.Header.UserArea)
	if err := binary.Read(userArea, binary.LittleEndian, &a.Info); err != nil {
		return err
	}
	totalACM := make([]byte, a.Header.GetSize()/4)
	a.Header.Write(totalACM)
	buf := bytes.NewReader(totalACM)
	_, err := buf.Seek(int64(a.Info.ChipsetIDList), io.SeekStart)
	if err != nil {
		return fmt.Errorf("unable to seek: %w", err)
	}
	if err := binary.Read(buf, binary.LittleEndian, &a.Chipsets.Count); err != nil {
		return err
	}
	a.Chipsets.IDList = make([]ChipsetID, a.Chipsets.Count)
	if err := binary.Read(buf, binary.LittleEndian, &a.Chipsets.IDList); err != nil {
		return err
	}
	_, err = buf.Seek(int64(a.Info.ProcessorIDList), io.SeekStart)
	if err != nil {
		return fmt.Errorf("unable to seek: %w", err)
	}
	if err := binary.Read(buf, binary.LittleEndian, &a.Processors.Count); err != nil {
		return err
	}
	a.Processors.IDList = make([]ProcessorID, a.Processors.Count)
	if err := binary.Read(buf, binary.LittleEndian, &a.Processors.IDList); err != nil {
		return err
	}
	_, err = buf.Seek(int64(a.Info.TPMInfoList), io.SeekStart)
	if err != nil {
		return fmt.Errorf("unable to seek: %w", err)
	}
	if err := binary.Read(buf, binary.LittleEndian, &a.TPMs.Capabilities); err != nil {
		return err
	}
	if err := binary.Read(buf, binary.LittleEndian, &a.TPMs.Count); err != nil {
		return err
	}
	a.TPMs.AlgID = make([]tpm2.Algorithm, a.TPMs.Count)
	if err := binary.Read(buf, binary.LittleEndian, &a.TPMs.AlgID); err != nil {
		return err
	}
	return nil
}

// ParseACM deconstructs a byte array containing the raw ACM into it's components
func ParseACM(r io.Reader) (*ACM, error) {
	var acm ACM
	var err error
	acm.Header, err = fit.ParseSACMData(r)
	if err != nil {
		return nil, err
	}
	if (acm.Header.GetModuleSubType() & ACMModuleSubtypeAncModule) > 0 {
		// ANC modules do not have an ACMINFO header
		return &acm, nil
	}
	if err := acm.ParseACMInfo(); err != nil {
		return nil, err
	}
	return &acm, nil
}

// ParseACMFlags parses the ACM Header flags
func (a *ACM) ParseACMFlags() *ACMFlags {
	var flags ACMFlags
	raw := a.Header.GetFlags()
	flags.Production = (raw>>15)&1 == 0 && (raw>>14)&1 == 0
	flags.PreProduction = (raw>>14)&1 != 0
	flags.DebugSigned = (raw>>15)&1 != 0
	return &flags
}

func LookupACMSize(header []byte) (int64, error) {
	var acmSize uint32
	buf := bytes.NewReader(header[:32])
	_, err := buf.Seek(ACMSizeOffset, io.SeekStart)
	if err != nil {
		return 0, fmt.Errorf("unable to seek: %w", err)
	}
	err = binary.Read(buf, binary.LittleEndian, &acmSize)
	if err != nil {
		return 0, err
	}
	return int64(acmSize * 4), nil
}

// PrettyPrint prints a human readable representation of the ACMHeader
func (a *ACM) PrettyPrintHeader() {
	fmt.Println("----Authenticated Code Module----")
	fmt.Println()
	if a.Header.GetModuleVendor() == ACMVendorIntel {
		fmt.Println("   Module Vendor: Intel")
	} else {
		fmt.Println("   Module Vendor: Unknown")
	}

	if a.Header.GetModuleType() == ACMTypeChipset {
		fmt.Println("   Module Type: ACM_TYPE_CHIPSET")
	} else {
		fmt.Println("   Module Type: UNKNOWN")
	}

	if uint16(a.Header.GetModuleSubType()) == ACMSubTypeReset {
		fmt.Println("   Module Subtype: Execute at Reset")
	} else if uint16(a.Header.GetModuleSubType()) == 0 {
		fmt.Println("   Module Subtype: 0x0")
	} else {
		fmt.Println("   Module Subtype: Unknown")
	}
	flags := a.ParseACMFlags()
	fmt.Println("   Flags:")
	fmt.Printf("      Production: %t\n", flags.Production)
	fmt.Printf("      Pre-Production:  %t\n", flags.PreProduction)
	fmt.Printf("      Debug Signed:  %t\n", flags.DebugSigned)
	fmt.Printf("   Module Date: 0x%02x\n", a.Header.GetDate())
	fmt.Printf("   Module Size: 0x%x (%d)\n", a.Header.GetSize(), a.Header.GetSize())

	fmt.Printf("   Header Length: 0x%x (%d)\n", a.Header.GetHeaderLen(), a.Header.GetHeaderLen())
	fmt.Printf("   Header Version: %d\n", a.Header.GetHeaderVersion())
	fmt.Printf("   Chipset ID: 0x%02x\n", a.Header.GetChipsetID())
	fmt.Printf("   Flags: 0x%02x\n", a.Header.GetFlags())
	fmt.Printf("   TXT SVN: 0x%08x\n", a.Header.GetTXTSVN())
	fmt.Printf("   SE SVN: 0x%08x\n", a.Header.GetSESVN())
	fmt.Printf("   Code Control: 0x%02x\n", a.Header.GetCodeControl())
	fmt.Printf("   Entry Point: 0x%08x:%08x\n", a.Header.GetSegSel(), a.Header.GetEntryPoint())
	fmt.Printf("   Scratch Size: 0x%x (%d)\n", a.Header.GetScratchSize(), a.Header.GetScratchSize())
	fmt.Println()
}

// PrettyPrint prints a human readable representation of the Chipsets
func (c Chipsets) PrettyPrint() {
	fmt.Println("   --Chipset List--")
	fmt.Printf("      Entries: %d\n", c.Count)
	for idx, chipset := range c.IDList {
		fmt.Printf("      Entry %d:\n", idx)
		fmt.Printf("         Flags: 0x%02x\n", chipset.Flags)
		fmt.Printf("         Vendor: 0x%02x\n", chipset.VendorID)
		fmt.Printf("         Device: 0x%02x\n", chipset.DeviceID)
		fmt.Printf("         Revision: 0x%02x\n", chipset.RevisionID)
	}
	fmt.Println()
}

// PrettyPrint prints a human readable representation of the Processors
func (p Processors) PrettyPrint() {
	fmt.Println("   --Processor List--")
	fmt.Printf("      Entries: %d\n", p.Count)
	for idx, processor := range p.IDList {
		fmt.Printf("      Entry %d:\n", idx)
		fmt.Printf("         FMS: 0x%02x\n", processor.FMS)
		fmt.Printf("         FMS Maks: 0x%02x\n", processor.FMSMask)
		fmt.Printf("         Platform ID: 0x%02x\n", processor.PlatformID)
		fmt.Printf("         Platform Mask: 0x%02x\n", processor.PlatformMask)
	}
	fmt.Println()
}

// PrettyPrint prints a human readable representation of the TPMs
func (t TPMs) PrettyPrint() {
	fmt.Println("   --TPM Info List--")
	fmt.Println("      Capabilities:")
	fmt.Printf("         External Policy: %02x\n", t.Capabilities)
	fmt.Printf("      Algorithms: %d\n", t.Count)
	for _, algo := range t.AlgID {
		fmt.Printf("         %v\n", algo.String())
	}
	fmt.Println()
}

// PrettyPrint prints a human readable representation of the ACM
func (a *ACM) PrettyPrint() {
	a.PrettyPrintHeader()
	fmt.Println("   --Info Table--")
	switch a.Info.ChipsetACMType {
	case ACMChipsetTypeBios:
		fmt.Println("      Chipset ACM: BIOS")
	case ACMChipsetTypeBiosRevoc:
		fmt.Println("      Chipset ACM: BIOS Revocation")
	case ACMChipsetTypeSinit:
		fmt.Println("      Chipset ACM: SINIT")
	case ACMChipsetTypeSinitRevoc:
		fmt.Println("      Chipset ACM: SINIT Revocation")
	default:
		fmt.Println("      Chipset ACM: Unknown")
	}
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
		fmt.Printf("      Version: %d\n", a.Info.Version)
		fmt.Printf("      Length: 0x%x (%d)\n", a.Info.Length, a.Info.Length)
		fmt.Printf("      Chipset ID List: 0x%02x\n", a.Info.ChipsetIDList)
		fmt.Printf("      OS SINIT Data Version: 0x%02x\n", a.Info.OSSinitDataVersion)
		fmt.Printf("      Min. MLE Header Version: 0x%08x\n", a.Info.MinMleHeaderVersion)
		fmt.Printf("      Capabilities: 0x%08x\n", a.Info.TxtCaps)
		fmt.Printf("      ACM Version: %d\n", a.Info.ACMVersion)
		fmt.Printf("      ACM Revision: %s\n", a.Info.ACMRevision)
		fmt.Printf("      Processor ID List: 0x%02x\n", a.Info.ProcessorIDList)
		fmt.Printf("      TPM ID List: 0x%02x\n", a.Info.TPMInfoList)
		fmt.Println()
		a.Chipsets.PrettyPrint()
		a.Processors.PrettyPrint()
		a.TPMs.PrettyPrint()
	} else {
		fmt.Println("      UUID: ACM_UUID_V0")
		fmt.Println()
	}
}
