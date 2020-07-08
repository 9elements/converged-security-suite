package test

import (
	"bytes"
	"encoding/binary"
	"fmt"

	"github.com/9elements/txt-suite/pkg/hwapi"
	"github.com/9elements/txt-suite/pkg/tools"
)

// FITSize 16MiB
const FITSize int64 = 16 * 1024 * 1024

// FourGiB 4Gigabyte
const FourGiB int64 = 0x100000000

// ResetVector is the reset vector address
const ResetVector = 0xFFFFFFF0

// FITVector is the FIT Vector address
const FITVector = 0xFFFFFFC0

// ValidFitRange is the size of a correct FIT
const ValidFitRange = 0xFF000000

var (
	fitImage []byte
	// set by FITVectorIsSet
	fitPointer uint32
	// set by testhasfit
	fit []tools.FitEntry

	testfitvectorisset = Test{
		Name:                    "Valid FIT vector",
		Required:                true,
		function:                FITVectorIsSet,
		Status:                  Implemented,
		SpecificationChapter:    "3.0 FIT Pointer",
		SpecificiationTitle:     IntelFITSpecificationTitle,
		SpecificationDocumentID: IntelFITSpecificationDocumentID,
	}
	testhasfit = Test{
		Name:                    "Valid FIT",
		Required:                true,
		function:                HasFIT,
		dependencies:            []*Test{&testfitvectorisset},
		Status:                  Implemented,
		SpecificationChapter:    "4.0 Firmware Interface Table",
		SpecificiationTitle:     IntelFITSpecificationTitle,
		SpecificationDocumentID: IntelFITSpecificationDocumentID,
	}
	testhasbiosacm = Test{
		Name:                    "BIOS ACM entry in FIT",
		Required:                true,
		function:                HasBIOSACM,
		dependencies:            []*Test{&testhasfit},
		Status:                  Implemented,
		SpecificationChapter:    "4.4 Startup ACM (Type 2) Rules",
		SpecificiationTitle:     IntelFITSpecificationTitle,
		SpecificationDocumentID: IntelFITSpecificationDocumentID,
	}
	testhasibb = Test{
		Name:                    "IBB entry in FIT",
		Required:                true,
		function:                HasIBB,
		dependencies:            []*Test{&testhasfit},
		Status:                  Implemented,
		SpecificationChapter:    "4.6 BIOS Startup Module (Type 7) Rules",
		SpecificiationTitle:     IntelFITSpecificationTitle,
		SpecificationDocumentID: IntelFITSpecificationDocumentID,
	}
	// Not mandatory, LCP_POLICY_DATA file may be supplied by GRUB to TBOOT
	testhaslcpTest = Test{
		Name:         "LCP Policy entry in FIT",
		Required:     false,
		NonCritical:  true,
		function:     HasBIOSPolicy,
		dependencies: []*Test{&testhasfit},
		Status:       Implemented,
	}
	testibbcoversresetvector = Test{
		Name:                    "IBB covers reset vector",
		Required:                true,
		function:                IBBCoversResetVector,
		dependencies:            []*Test{&testhasfit, &testhasibb},
		Status:                  Implemented,
		SpecificationChapter:    "4.6 BIOS Startup Module (Type 7) Rules",
		SpecificiationTitle:     IntelFITSpecificationTitle,
		SpecificationDocumentID: IntelFITSpecificationDocumentID,
	}
	testibbcoversfitvector = Test{
		Name:                    "IBB covers FIT vector",
		Required:                true,
		function:                IBBCoversFITVector,
		dependencies:            []*Test{&testhasfit, &testhasibb},
		Status:                  Implemented,
		SpecificationChapter:    "4.6 BIOS Startup Module (Type 7) Rules",
		SpecificiationTitle:     IntelFITSpecificationTitle,
		SpecificationDocumentID: IntelFITSpecificationDocumentID,
	}
	testibbcoversfit = Test{
		Name:         "IBB covers FIT",
		Required:     true,
		function:     IBBCoversFIT,
		dependencies: []*Test{&testhasfit, &testhasibb},
		Status:       Implemented,
	}
	testnoibboverlap = Test{
		Name:                    "IBBs doesn't overlap each other",
		Required:                true,
		function:                NoIBBOverlap,
		dependencies:            []*Test{&testhasfit, &testhasibb},
		Status:                  Implemented,
		SpecificationChapter:    "4.6 BIOS Startup Module (Type 7) Rules",
		SpecificiationTitle:     IntelFITSpecificationTitle,
		SpecificationDocumentID: IntelFITSpecificationDocumentID,
	}
	testnobiosacmoverlap = Test{
		Name:                    "BIOS ACM does not overlap IBBs",
		Required:                true,
		function:                NoBIOSACMOverlap,
		dependencies:            []*Test{&testhasfit, &testhasbiosacm},
		Status:                  Implemented,
		SpecificationChapter:    "4.6 BIOS Startup Module (Type 7) Rules",
		SpecificiationTitle:     IntelFITSpecificationTitle,
		SpecificationDocumentID: IntelFITSpecificationDocumentID,
	}
	testnobiosacmisbelow4g = Test{
		Name:                    "IBB and BIOS ACM below 4GiB",
		Required:                true,
		function:                BIOSACMIsBelow4G,
		dependencies:            []*Test{&testhasfit, &testhasbiosacm},
		Status:                  Implemented,
		SpecificationChapter:    "2.2 FIT Pointer Rules",
		SpecificiationTitle:     IntelTXTBGSBIOSSpecificationTitle,
		SpecificationDocumentID: IntelTXTBGSBIOSSpecificationDocumentID,
	}
	testpolicyallowstxt = Test{
		Name:                    "TXT not disabled by LCP Policy",
		Required:                true,
		function:                PolicyAllowsTXT,
		dependencies:            []*Test{&testhasfit},
		Status:                  Implemented,
		SpecificationChapter:    "B.1.6 TXT.SPAD – BOOTSTATUS",
		SpecificiationTitle:     IntelTXTSpecificationTitle,
		SpecificationDocumentID: IntelTXTSpecificationDocumentID,
	}
	testbiosacmvalid = Test{
		Name:                    "BIOSACM header valid",
		Required:                true,
		function:                BIOSACMValid,
		dependencies:            []*Test{&testhasfit, &testhasbiosacm},
		Status:                  Implemented,
		SpecificationChapter:    "A.1 Authenticated Code Module Format",
		SpecificiationTitle:     IntelTXTSpecificationTitle,
		SpecificationDocumentID: IntelTXTSpecificationDocumentID,
	}
	testbiosacmsizecorrect = Test{
		Name:                    "BIOSACM size check",
		Required:                true,
		function:                BIOSACMSizeCorrect,
		dependencies:            []*Test{&testhasfit, &testhasbiosacm},
		Status:                  Implemented,
		SpecificationChapter:    "A.1 Authenticated Code Module Format",
		SpecificiationTitle:     IntelTXTSpecificationTitle,
		SpecificationDocumentID: IntelTXTSpecificationDocumentID,
	}
	testbiosacmaligmentcorrect = Test{
		Name:                    "BIOSACM alignment check",
		Required:                true,
		function:                BIOSACMAlignmentCorrect,
		dependencies:            []*Test{&testhasfit, &testhasbiosacm},
		Status:                  Implemented,
		SpecificationChapter:    "A.1.1 Memory Type Cacheability Restrictions",
		SpecificiationTitle:     IntelTXTSpecificationTitle,
		SpecificationDocumentID: IntelTXTSpecificationDocumentID,
	}
	testbiosacmmatcheschipset = Test{
		Name:                    "BIOSACM matches chipset",
		Required:                true,
		function:                BIOSACMMatchesChipset,
		dependencies:            []*Test{&testhasfit, &testhasbiosacm},
		Status:                  Implemented,
		SpecificationChapter:    "2.2.3.1 Matching an AC Module to the Platform",
		SpecificiationTitle:     IntelTXTSpecificationTitle,
		SpecificationDocumentID: IntelTXTSpecificationDocumentID,
	}
	testbiosacmmatchescpu = Test{
		Name:                    "BIOSACM matches processor",
		Required:                true,
		function:                BIOSACMMatchesCPU,
		dependencies:            []*Test{&testhasfit, &testhasbiosacm},
		Status:                  Implemented,
		SpecificationChapter:    "2.2.3.1 Matching an AC Module to the Platform",
		SpecificiationTitle:     IntelTXTSpecificationTitle,
		SpecificationDocumentID: IntelTXTSpecificationDocumentID,
	}

	// TestsFIT exports the Slice with FIT tests
	TestsFIT = [...]*Test{
		&testfitvectorisset,
		&testhasfit,
		&testhasbiosacm,
		&testhasibb,
		&testhaslcpTest,
		&testibbcoversresetvector,
		&testibbcoversfitvector,
		&testibbcoversfit,
		&testnoibboverlap,
		&testnobiosacmoverlap,
		&testnobiosacmisbelow4g,
		&testpolicyallowstxt,
		&testbiosacmvalid,
		&testbiosacmsizecorrect,
		&testbiosacmaligmentcorrect,
		&testbiosacmmatcheschipset,
		&testbiosacmmatchescpu,
	}
)

// FITVectorIsSet checks if the FIT Vector is set
func FITVectorIsSet(txtAPI hwapi.APIInterfaces) (bool, error, error) {
	fitvec := make([]byte, 4)
	err := txtAPI.ReadPhysBuf(FITVector, fitvec)

	if err != nil {
		return false, nil, err
	}

	buf := bytes.NewReader(fitvec)
	err = binary.Read(buf, binary.LittleEndian, &fitPointer)
	if err != nil {
		return false, nil, err
	}

	if fitPointer < ValidFitRange {
		return false, fmt.Errorf("FitPointer must be in ValidFitRange - See Intel Firmware Interface Table BIOS Specification Document Number: 338505-001, P. 6"), nil
	}
	if fitPointer >= ResetVector {
		return false, fmt.Errorf("FitPointer must be smaller than ResetVector - See Intel Firmware Interface Table BIOS Specification Document Number: 338505-001, P. 6"), nil
	}

	return true, nil, nil
}

// HasFIT checks if the FIT is present
func HasFIT(txtAPI hwapi.APIInterfaces) (bool, error, error) {
	fithdr := make([]byte, 16)
	err := txtAPI.ReadPhysBuf(int64(fitPointer), fithdr)
	if err != nil {
		return false, nil, err
	}

	hdr, err := tools.GetFitHeader(fithdr)
	if err != nil {
		return false, nil, err
	}

	if int64(fitPointer)+int64(hdr.Size()) > FourGiB {
		return false, fmt.Errorf("FIT isn't part of 32bit address-space - See Intel Firmware Interface Table BIOS Specification Document Number: 338505-001, P. 6"), nil
	}

	fitblob := make([]byte, hdr.Size())
	err = txtAPI.ReadPhysBuf(int64(fitPointer), fitblob)

	fit, err = tools.ExtractFit(fitblob)
	if err != nil {
		return false, nil, err
	}

	if fit == nil {
		return false, fmt.Errorf("FIT-Error: Referenz is nil"), nil
	}
	return true, nil, nil
}

// HasBIOSACM checks if FIT table has BIOSACM entry
func HasBIOSACM(txtAPI hwapi.APIInterfaces) (bool, error, error) {
	count := 0
	for _, ent := range fit {
		if ent.Type() == tools.StartUpACMod {
			count++
		}
	}
	if count == 0 {
		return false, fmt.Errorf("Fit has no Startup AC Module Entry, but at least one is required - See Intel Firmware Interface Table BIOS Specification Document Number: 338505-001, P. 9"), nil
	}
	return true, nil, nil
}

// HasIBB checks if FIT table has BIOS Startup Module entry
func HasIBB(txtAPI hwapi.APIInterfaces) (bool, error, error) {
	for _, ent := range fit {
		if ent.Type() == tools.BIOSStartUpMod {
			return true, nil, nil
		}
	}

	return false, fmt.Errorf("Fit has no BIOS Startup Module Entry, but at least one is required - See Intel Firmware Interface Table BIOS Specification Document Number: 338505-001, P. 10"), nil
}

// HasBIOSPolicy checks if FIT table has ONE BIOS Policy Data Record Entry
func HasBIOSPolicy(txtAPI hwapi.APIInterfaces) (bool, error, error) {
	count := 0
	for _, ent := range fit {
		if ent.Type() == tools.BIOSPolicyRec {
			count++
		}
	}
	if count == 0 {
		return false, fmt.Errorf("Fit has no BIOS Policy Data Record Entry - See Intel Firmware Interface Table BIOS Specification Document Number: 338505-001, P. 11"), nil
	}

	if count > 1 {
		return false, fmt.Errorf("Fit has more than 1 BIOS Policy Data Record Entry, only one is allowed - See Intel Firmware Interface Table BIOS Specification Document Number: 338505-001, P. 11"), nil
	}
	return true, nil, nil
}

// IBBCoversResetVector checks if BIOS Startup Module Entry covers Reset Vector
func IBBCoversResetVector(txtAPI hwapi.APIInterfaces) (bool, error, error) {
	for _, ent := range fit {
		if ent.Type() == tools.BIOSStartUpMod {
			coversRv := ent.Address <= ResetVector && ent.Address+uint64(ent.Size()) >= ResetVector+4

			if coversRv {
				return true, nil, nil
			}
		}
	}

	return false, fmt.Errorf("BIOS Startup Module Entry must cover Reset Vector"), nil
}

// IBBCoversFITVector checks if BIOS Startup Module Entry covers FIT vector
func IBBCoversFITVector(txtAPI hwapi.APIInterfaces) (bool, error, error) {
	for _, ent := range fit {
		if ent.Type() == tools.BIOSStartUpMod {
			coversRv := ent.Address <= FITVector && ent.Address+uint64(ent.Size()) >= FITVector+4

			if coversRv {
				return true, nil, nil
			}
		}
	}

	return false, fmt.Errorf("BIOS Startup Module Entry must cover Firmware Interface Table Vector"), nil
}

// IBBCoversFIT checks if BIOS Startup Module Entry covers FIT tabel
func IBBCoversFIT(txtAPI hwapi.APIInterfaces) (bool, error, error) {
	for _, ent := range fit {
		if ent.Type() == tools.BIOSStartUpMod {
			coversRv := ent.Address <= uint64(fitPointer) && ent.Address+uint64(ent.Size()) >= uint64(fitPointer+uint32(len(fit)*16))

			if coversRv {
				return true, nil, nil
			}
		}
	}

	return false, fmt.Errorf("BIOS Startup Module Entry must cover Firmware Interface Table"), nil
}

// NoIBBOverlap checks if BIOS Startup Module Entries overlap
func NoIBBOverlap(txtAPI hwapi.APIInterfaces) (bool, error, error) {
	for i, ent1 := range fit {
		if ent1.Type() == tools.BIOSStartUpMod {
			for j, ent2 := range fit {
				if i < j && ent2.Type() == tools.BIOSStartUpMod {
					a := ent1.Address > ent2.Address+uint64(ent2.Size())
					b := ent2.Address > ent1.Address+uint64(ent1.Size())

					if !a && !b {
						return false, fmt.Errorf("BIOS Startup Module Entries overlap "), nil
					}
				}
			}
		}
	}

	return true, nil, nil
}

// NoBIOSACMOverlap checks if BIOS ACM Entries Overlap
func NoBIOSACMOverlap(txtAPI hwapi.APIInterfaces) (bool, error, error) {
	for i, ent1 := range fit {
		if ent1.Type() == tools.BIOSStartUpMod {
			for j, ent2 := range fit {
				if i < j && ent2.Type() == tools.StartUpACMod {
					a := ent1.Address > ent2.Address+uint64(ent2.Size())
					b := ent2.Address > ent1.Address+uint64(ent1.Size())

					if !a && !b {
						return false, fmt.Errorf("Startup AC Module Entries overlap"), nil
					}
				}
			}
		}
	}

	return true, nil, nil
}

// BIOSACMIsBelow4G checks if BIOS ACM is below 4Gb (has a valid address)
func BIOSACMIsBelow4G(txtAPI hwapi.APIInterfaces) (bool, error, error) {
	for _, ent := range fit {
		if ent.Type() == tools.StartUpACMod {
			if ent.Address+uint64(ent.Size()) > uint64(FourGiB) {
				return false, fmt.Errorf("Startup AC Module Entry is above 4Gib"), nil
			}
		}
	}

	return true, nil, nil
}

// PolicyAllowsTXT checks if Record matches TXT requirements.
func PolicyAllowsTXT(txtAPI hwapi.APIInterfaces) (bool, error, error) {
	for _, ent := range fit {
		if ent.Type() == tools.TXTPolicyRec {
			switch ent.Version {
			case 0:
				return false, fmt.Errorf("Indexed IO type pointer are not supported - See Intel Firmware Interface Table BIOS Specification Document Number: 338505-001, P. 11"), nil
			case 1:
				var b hwapi.Uint8

				err := txtAPI.ReadPhys(int64(ent.Address), &b)
				if err != nil {
					return false, nil, err
				}

				return b&1 != 0, nil, nil
			default:
				return false, fmt.Errorf("Unknown TXT policy record version %d - See Intel Firmware Interface Table BIOS Specification Document Number: 338505-001, P. 11", ent.Version), nil
			}
		}
	}

	// No record means TXT is enabled
	return true, nil, nil
}

// BIOSACMValid checks if BIOS ACM is valid
func BIOSACMValid(txtAPI hwapi.APIInterfaces) (bool, error, error) {
	acm, _, _, _, err := biosACM(txtAPI, fit)

	return acm != nil, nil, err
}

// BIOSACMSizeCorrect checks if BIOS ACM size is correct
func BIOSACMSizeCorrect(txtAPI hwapi.APIInterfaces) (bool, error, error) {
	acm, _, _, _, err := biosACM(txtAPI, fit)
	if err != nil {
		return false, nil, err
	}

	if acm.Header.Size%64 != 0 {
		return false, fmt.Errorf("BIOSACM Size is not correct "), nil
	}
	return true, nil, nil
}

// BIOSACMAlignmentCorrect checks if BIOS ACM alignment is correct
func BIOSACMAlignmentCorrect(txtAPI hwapi.APIInterfaces) (bool, error, error) {
	for _, ent := range fit {
		if ent.Type() == tools.StartUpACMod {
			return ent.Address%(128*1024) == 0, nil, nil
		}
	}

	return false, fmt.Errorf("no BIOS ACM in FIT"), nil
}

// BIOSACMMatchesChipset checks if BIOS ACM matches chipset
func BIOSACMMatchesChipset(txtAPI hwapi.APIInterfaces) (bool, error, error) {
	_, chp, _, _, err := biosACM(txtAPI, fit)

	if err != nil {
		return false, nil, err
	}
	buf, err := tools.FetchTXTRegs(txtAPI)
	if err != nil {
		return false, nil, err
	}
	txt, err := tools.ParseTXTRegs(buf)
	if err != nil {
		return false, nil, err
	}

	for _, ch := range chp.IDList {
		a := ch.VendorID == txt.Vid
		b := ch.DeviceID == txt.Did

		if a && b {
			if ch.Flags&1 != 0 {
				if ch.RevisionID&txt.Rid > 0 {
					return true, nil, nil
				}
			} else {
				if ch.RevisionID == txt.Rid {
					return true, nil, nil
				}
			}
		}
	}

	return false, fmt.Errorf("BIOS StartUp Module and Chipset doens't match"), nil
}

// BIOSACMMatchesCPU checks if BIOS ACM matches CPU
func BIOSACMMatchesCPU(txtAPI hwapi.APIInterfaces) (bool, error, error) {
	_, _, cpus, _, err := biosACM(txtAPI, fit)
	if err != nil {
		return false, nil, err
	}

	// IA32_PLATFORM_ID
	platform, err := txtAPI.IA32PlatformID()
	if err != nil {
		return false, nil, err
	}

	fms := txtAPI.CPUSignature()

	for _, cpu := range cpus.IDList {
		a := fms&cpu.FMSMask == cpu.FMS
		b := platform&cpu.PlatformMask == cpu.PlatformID

		if a && b {
			return true, nil, nil
		}
	}

	return false, fmt.Errorf("BIOS Startup Module and CPU doesn't match"), nil
}

func biosACM(txtAPI hwapi.APIInterfaces, fit []tools.FitEntry) (*tools.ACM, *tools.Chipsets, *tools.Processors, *tools.TPMs, error) {
	for _, ent := range fit {
		if ent.Type() == tools.StartUpACMod {
			buf1 := make([]byte, tools.ACMheaderLen*4)

			err := txtAPI.ReadPhysBuf(int64(ent.Address), buf1)

			if err != nil {
				return nil, nil, nil, nil, fmt.Errorf("ReadPhysBuf failed at %v with error: %v", ent.Address, err)
			}

			acm, err := tools.ParseACMHeader(buf1)
			if err != nil {
				return nil, nil, nil, nil, fmt.Errorf("Can't Parse BIOS ACM header correctly")
			}

			ret, err := tools.ValidateACMHeader(acm)

			if ret == false {
				return nil, nil, nil, nil, fmt.Errorf("Validating BIOS ACM Header failed: %v", err)
			}

			buf2 := make([]byte, acm.Size*4)
			err = txtAPI.ReadPhysBuf(int64(ent.Address), buf2)

			if err != nil {
				return nil, nil, nil, nil, fmt.Errorf("Cant read BIOS ACM completly")
			}

			return tools.ParseACM(buf2)
		}
	}

	return nil, nil, nil, nil, fmt.Errorf("no BIOS ACM in FIT")
}
