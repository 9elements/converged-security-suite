package test

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"os"

	"github.com/9elements/converged-security-suite/pkg/hwapi"
)

func notImplemented(txtAPI hwapi.APIInterfaces) (bool, error, error) {
	return false, nil, fmt.Errorf("Not implemented")
}

var (
	testRSDPChecksum = Test{
		Name:                    "ACPI RSDP has valid checksum",
		Required:                true,
		function:                notImplemented,
		Status:                  NotImplemented,
		SpecificationChapter:    "SINIT Class 0xC Major 1",
		SpecificiationTitle:     ServerGrantleyPlatformSpecificationTitle,
		SpecificationDocumentID: ServerGrantleyPlatformDocumentID,
	}
	testRSDTChecksum = Test{
		Name:                    "ACPI RSDT present",
		Required:                true,
		function:                notImplemented,
		Status:                  NotImplemented,
		SpecificationChapter:    "SINIT Class 0xC Major 2",
		SpecificiationTitle:     ServerGrantleyPlatformSpecificationTitle,
		SpecificationDocumentID: ServerGrantleyPlatformDocumentID,
	}
	testRSDTValid = Test{
		Name:                    "ACPI RSDT is valid",
		Required:                true,
		function:                notImplemented,
		Status:                  NotImplemented,
		SpecificationChapter:    "SINIT Class 0xC Major 3",
		SpecificiationTitle:     ServerGrantleyPlatformSpecificationTitle,
		SpecificationDocumentID: ServerGrantleyPlatformDocumentID,
	}
	testDMARPresent = Test{
		Name:                    "ACPI DMAR is present",
		Required:                true,
		function:                CheckDMARPresence,
		Status:                  Implemented,
		SpecificationChapter:    "SINIT Class 0xC Major 4",
		SpecificiationTitle:     ServerGrantleyPlatformSpecificationTitle,
		SpecificationDocumentID: ServerGrantleyPlatformDocumentID,
	}
	testDMARValid = Test{
		Name:                    "ACPI DMAR is valid",
		Required:                true,
		function:                CheckDMARValid,
		Status:                  Implemented,
		SpecificationChapter:    "SINIT Class 0xC Major 5",
		SpecificiationTitle:     ServerGrantleyPlatformSpecificationTitle,
		SpecificationDocumentID: ServerGrantleyPlatformDocumentID,
		dependencies:            []*Test{&testDMARPresent},
	}
	testMADTPresent = Test{
		Name:                    "ACPI MADT is present",
		Required:                true,
		function:                CheckMADTPresence,
		Status:                  Implemented,
		SpecificationChapter:    "SINIT Class 0xC Major 16",
		SpecificiationTitle:     ServerGrantleyPlatformSpecificationTitle,
		SpecificationDocumentID: ServerGrantleyPlatformDocumentID,
	}
	testMADTValid = Test{
		Name:                    "ACPI MADT is valid",
		Required:                true,
		function:                CheckMADTValid,
		Status:                  Implemented,
		SpecificationChapter:    "SINIT Class 0xC Major 7",
		SpecificiationTitle:     ServerGrantleyPlatformSpecificationTitle,
		SpecificationDocumentID: ServerGrantleyPlatformDocumentID,
		dependencies:            []*Test{&testMADTPresent},
	}
	testRSDPValid = Test{
		Name:                    "ACPI RSDP is valid",
		Required:                true,
		function:                notImplemented,
		Status:                  NotImplemented,
		SpecificationChapter:    "SINIT Class 0xC Major 8",
		SpecificiationTitle:     ServerGrantleyPlatformSpecificationTitle,
		SpecificationDocumentID: ServerGrantleyPlatformDocumentID,
	}
	testXSDTValid = Test{
		Name:                    "ACPI XSDT is valid",
		Required:                true,
		function:                notImplemented,
		Status:                  NotImplemented,
		SpecificationChapter:    "SINIT Class 0xC Major 9",
		SpecificiationTitle:     ServerGrantleyPlatformSpecificationTitle,
		SpecificationDocumentID: ServerGrantleyPlatformDocumentID,
	}

	testTXTHeapSizeFitsMADTCopy = Test{
		Name:                    "ACPI MADT copy fits into TXT heap",
		Required:                true,
		function:                notImplemented,
		Status:                  NotImplemented,
		SpecificationChapter:    "SINIT Class 9 Major 7 Minor 1",
		SpecificiationTitle:     ServerGrantleyPlatformSpecificationTitle,
		SpecificationDocumentID: ServerGrantleyPlatformDocumentID,
	}
	testTXTHeapSizeFitsDynamicMadt = Test{
		Name:                    "Dynamic ACPI MADT fits into TXT heap",
		Required:                true,
		function:                notImplemented,
		Status:                  NotImplemented,
		SpecificationChapter:    "SINIT Class 9 Major 7 Minor 2",
		SpecificiationTitle:     ServerGrantleyPlatformSpecificationTitle,
		SpecificationDocumentID: ServerGrantleyPlatformDocumentID,
	}
	testTXTHeapSizeFitsDMARCopy = Test{
		Name:                    "ACPI DMAR copy fits into TXT heap",
		Required:                true,
		function:                notImplemented,
		Status:                  NotImplemented,
		SpecificationChapter:    "SINIT Class 9 Major 7 Minor 3",
		SpecificiationTitle:     ServerGrantleyPlatformSpecificationTitle,
		SpecificationDocumentID: ServerGrantleyPlatformDocumentID,
	}
	testACPIRSDPInOSToSINITData = Test{
		Name:                    "ACPI RSDP in 'OS to SINIT data' points to address below 4 GiB",
		Required:                true,
		function:                notImplemented,
		Status:                  NotImplemented,
		SpecificationChapter:    "SINIT Class 9 Major 0xc",
		SpecificiationTitle:     ServerGrantleyPlatformSpecificationTitle,
		SpecificationDocumentID: ServerGrantleyPlatformDocumentID,
	}
	testACPIDMARValidHPET = Test{
		Name:                    "ACPI DMAR table has valid HPET configuration",
		Required:                true,
		function:                notImplemented,
		Status:                  NotImplemented,
		SpecificationChapter:    "SINIT Class 0xA Major 3 Minor 1",
		SpecificiationTitle:     ServerGrantleyPlatformSpecificationTitle,
		SpecificationDocumentID: ServerGrantleyPlatformDocumentID,
	}
	testACPIDMARValidBus = Test{
		Name:                    "ACPI DMAR table has valid BUS configuration",
		Required:                true,
		function:                notImplemented,
		Status:                  NotImplemented,
		SpecificationChapter:    "SINIT Class 0xA Major 3 Minor 2",
		SpecificiationTitle:     ServerGrantleyPlatformSpecificationTitle,
		SpecificationDocumentID: ServerGrantleyPlatformDocumentID,
	}
	testACPIDMARValidAzalia = Test{
		Name:                    "ACPI DMAR table Azalia device scope is valid",
		Required:                true,
		function:                notImplemented,
		Status:                  NotImplemented,
		SpecificationChapter:    "SINIT Class 0xA Major 3 Minor 3",
		SpecificiationTitle:     ServerGrantleyPlatformSpecificationTitle,
		SpecificationDocumentID: ServerGrantleyPlatformDocumentID,
	}
	testACPIDMARDeviceScopePresent = Test{
		Name:                    "ACPI DMAR table device scope is present",
		Required:                true,
		function:                notImplemented,
		Status:                  NotImplemented,
		SpecificationChapter:    "SINIT Class 0xA Major 3 Minor 4",
		SpecificiationTitle:     ServerGrantleyPlatformSpecificationTitle,
		SpecificationDocumentID: ServerGrantleyPlatformDocumentID,
	}
	testACPIDMARHPETScopeDuplicated = Test{
		Name:                    "ACPI DMAR table has no duplicated HPET scope",
		Required:                true,
		function:                notImplemented,
		Status:                  NotImplemented,
		SpecificationChapter:    "SINIT Class 0xA Major 3 Minor 5",
		SpecificiationTitle:     ServerGrantleyPlatformSpecificationTitle,
		SpecificationDocumentID: ServerGrantleyPlatformDocumentID,
	}
	testACPIDMARDrhdVtdDevice = Test{
		Name:                    "ACPI DMAR table DRHD device ",
		Required:                true,
		function:                notImplemented,
		Status:                  NotImplemented,
		SpecificationChapter:    "SINIT Class 0xA Major 3 Minor 6",
		SpecificiationTitle:     ServerGrantleyPlatformSpecificationTitle,
		SpecificationDocumentID: ServerGrantleyPlatformDocumentID,
	}
	testACPIDMARDrhdVtdScope = Test{
		Name:                    "ACPI DMAR table DRHD device scope",
		Required:                true,
		function:                notImplemented,
		Status:                  NotImplemented,
		SpecificationChapter:    "SINIT Class 0xA Major 3 Minor 7",
		SpecificiationTitle:     ServerGrantleyPlatformSpecificationTitle,
		SpecificationDocumentID: ServerGrantleyPlatformDocumentID,
	}
	testACPIDMARDrhdPchApic = Test{
		Name:                    "ACPI DMAR table DRHD PCH APIC present",
		Required:                true,
		function:                notImplemented,
		Status:                  NotImplemented,
		SpecificationChapter:    "SINIT Class 0xA Major 3 Minor 8",
		SpecificiationTitle:     ServerGrantleyPlatformSpecificationTitle,
		SpecificationDocumentID: ServerGrantleyPlatformDocumentID,
	}
	testACPIDMARDrhdBaseaddressBelowFourGiB = Test{
		Name:                    "ACPI DMAR table DRHD base address below 4 GiB",
		Required:                true,
		function:                notImplemented,
		Status:                  NotImplemented,
		SpecificationChapter:    "SINIT Class 0xA Major 3 Minor 9",
		SpecificiationTitle:     ServerGrantleyPlatformSpecificationTitle,
		SpecificationDocumentID: ServerGrantleyPlatformDocumentID,
	}
	testACPIDMARDrhdTopaddressBelowFourGiB = Test{
		Name:                    "ACPI DMAR table DRHD top address below 4 GiB",
		Required:                true,
		function:                notImplemented,
		Status:                  NotImplemented,
		SpecificationChapter:    "SINIT Class 0xA Major 3 Minor 0xa",
		SpecificiationTitle:     ServerGrantleyPlatformSpecificationTitle,
		SpecificationDocumentID: ServerGrantleyPlatformDocumentID,
	}
	testACPIDMARDrhdBadDevicescopeEntry = Test{
		Name:                    "ACPI DMAR table DRHD device scope entries are valid",
		Required:                true,
		function:                notImplemented,
		Status:                  NotImplemented,
		SpecificationChapter:    "SINIT Class 0xA Major 3 Minor 0xb",
		SpecificiationTitle:     ServerGrantleyPlatformSpecificationTitle,
		SpecificationDocumentID: ServerGrantleyPlatformDocumentID,
	}
	testACPIDMARDrhdBadDevicescopeLength = Test{
		Name:                    "ACPI DMAR table DRHD device scope length are valid",
		Required:                true,
		function:                notImplemented,
		Status:                  NotImplemented,
		SpecificationChapter:    "SINIT Class 0xA Major 3 Minor 0xc",
		SpecificiationTitle:     ServerGrantleyPlatformSpecificationTitle,
		SpecificationDocumentID: ServerGrantleyPlatformDocumentID,
	}

	testACPIPWRMBarBelowFourGib = Test{
		Name:                    "ACPI PWRM BAR is below 4 GiB",
		Required:                true,
		function:                notImplemented,
		Status:                  NotImplemented,
		SpecificationChapter:    "SINIT Class 0x35 Major 4",
		SpecificiationTitle:     CBtGTXTPlatformSpecificationTitle,
		SpecificationDocumentID: CBtGTXTPlatformDocumentID,
	}
	testMCFGPresent = Test{
		Name:                    "ACPI MCFG is present",
		Required:                true,
		function:                CheckMCFGPresence,
		Status:                  Implemented,
		SpecificationChapter:    "SINIT Class 0xC Major 0xa",
		SpecificiationTitle:     CBtGTXTPlatformSpecificationTitle,
		SpecificationDocumentID: CBtGTXTPlatformDocumentID,
	}

	// TestsACPI exports the Slice with ACPI tests
	TestsACPI = [...]*Test{
		&testMCFGPresent,
		&testDMARPresent,
		&testDMARValid,
		&testMADTPresent,
		&testMADTValid,
	}
)

//ACPIHeader represent the table header as defined in ACPI Spec 6.2 "5.2.6 System Description Table Header"
type ACPIHeader struct {
	Signature       [4]uint8
	Length          uint32
	Revision        uint8
	Checksum        uint8
	OEMID           [6]uint8
	OEMTableID      [8]uint8
	OEMRevision     uint32
	CreatorID       uint32
	CreatorRevision uint32
}

func checkTableValid(txtAPI hwapi.APIInterfaces, name string) ([]byte, bool, error, error) {
	table, err := txtAPI.GetACPITable(name)
	if os.IsNotExist(err) {
		return nil, false, fmt.Errorf("ACPI table %s not found", name), nil
	} else if err != nil {
		return table, false, nil, err
	}

	var hdr ACPIHeader
	err = binary.Read(bytes.NewBuffer(table), binary.LittleEndian, &hdr)
	if err != nil {
		return table, false, nil, err
	}

	if hdr.Signature[0] != name[0] ||
		hdr.Signature[1] != name[1] ||
		hdr.Signature[2] != name[2] ||
		hdr.Signature[3] != name[3] {
		return table, false, fmt.Errorf("ACPI table %s has invalid signature", name), nil
	}

	if hdr.Length != uint32(len(table)) {
		return table, false, fmt.Errorf("ACPI table %s has invalid length", name), nil
	}

	chksum := byte(0)
	for _, i := range table {
		chksum = chksum + i
	}

	if chksum > 0 {
		return table, false, fmt.Errorf("ACPI table %s has invalid checksum", name), nil
	}

	return table, true, nil, nil
}

func checKPresence(txtAPI hwapi.APIInterfaces, name string) (bool, error, error) {
	_, err := txtAPI.GetACPITable(name)
	if os.IsNotExist(err) {
		return false, fmt.Errorf("ACPI table %s not found", name), nil
	} else if err != nil {
		return false, nil, err
	}
	return true, nil, nil
}

//CheckMCFGPresence tests if the MCFG ACPI table exists
func CheckMCFGPresence(txtAPI hwapi.APIInterfaces) (bool, error, error) {
	return checKPresence(txtAPI, "MCFG")
}

//CheckMADTPresence tests if the MADT ACPI table exists
func CheckMADTPresence(txtAPI hwapi.APIInterfaces) (bool, error, error) {
	return checKPresence(txtAPI, "MADT")
}

//ACPIMADT represent the table header as defined in ACPI Spec 6.2 "Multiple APIC Description Table (MADT) Format"
type ACPIMADT struct {
	ACPIHeader
	LapicAddress uint32
	Flags        uint32
	// TODO: interrupt controller structures
}

//CheckMADTValid tests if the MADT ACPI table is valid
func CheckMADTValid(txtAPI hwapi.APIInterfaces) (bool, error, error) {
	table, valid, err, interr := checkTableValid(txtAPI, "MADT")
	if interr != nil {
		return false, nil, interr
	} else if err != nil {
		return false, err, nil
	} else if !valid {
		return false, fmt.Errorf("ACPI table MADT not valid"), nil
	}

	var decoded ACPIMADT
	err = binary.Read(bytes.NewBuffer(table), binary.LittleEndian, &decoded)
	if err != nil {
		return false, nil, err
	}

	if decoded.Flags > 1 {
		return false, fmt.Errorf("Unknown flags in ACPI table MADT"), nil
	}
	return true, nil, nil
}

//CheckDMARPresence tests if the MADT ACPI table exists
func CheckDMARPresence(txtAPI hwapi.APIInterfaces) (bool, error, error) {
	return checKPresence(txtAPI, "DMAR")
}

//CheckDMARValid tests if the DMAR ACPI table is valid
func CheckDMARValid(txtAPI hwapi.APIInterfaces) (bool, error, error) {
	_, valid, err, interr := checkTableValid(txtAPI, "DMAR")
	if interr != nil {
		return false, nil, interr
	} else if err != nil {
		return false, err, nil
	} else if !valid {
		return false, fmt.Errorf("ACPI table DMAR not valid"), nil
	}

	//FIXME: Additional checks here
	return true, nil, nil
}
