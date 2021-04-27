package test

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"math"

	"github.com/9elements/converged-security-suite/v2/pkg/hwapi"
	"github.com/9elements/converged-security-suite/v2/pkg/intel/metadata/fit"
	"github.com/9elements/converged-security-suite/v2/pkg/tools"
)

// FITSize 16MiB
const FITSize int64 = 16 * 1024 * 1024

// FourGiB 4Gigabyte
const FourGiB = 0x100000000

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
	fitHeaders fit.Table

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
	testhasmcupdate = Test{
		Name:                    "Microcode update entry in FIT",
		Required:                true,
		function:                HasMicroCode,
		dependencies:            []*Test{&testhasfit},
		Status:                  Implemented,
		SpecificationChapter:    "4.4 Startup ACM (Type 2) Rules",
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
	testhaslcpTest = Test{
		Name:         "BIOS Policy entry in FIT",
		Required:     false,
		function:     HasBIOSPolicy,
		dependencies: []*Test{&testhasfit, &testtxtmodvalid},
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
	testacmsfornpw = Test{
		Name:                    "SINIT/BIOS ACM has no NPW flag set",
		Required:                true,
		function:                SINITandBIOSACMnoNPW,
		dependencies:            []*Test{&testhasfit, &testhasbiosacm},
		Status:                  Implemented,
		SpecificationChapter:    "4.1.4 Supported Platform Configurations",
		SpecificiationTitle:     IntelTXTBGSBIOSSpecificationTitle,
		SpecificationDocumentID: IntelTXTBGSBIOSSpecificationDocumentID,
	}
	testsinitacmupporttpm = Test{
		Name:                    "SINIT ACM supports used TPM",
		Required:                true,
		function:                SINITACMcomplyTPMSpec,
		dependencies:            []*Test{&testhasfit, &testhasbiosacm},
		Status:                  Implemented,
		SpecificationChapter:    "4.1.4 Supported Platform Configurations",
		SpecificiationTitle:     IntelTXTSpecificationTitle,
		SpecificationDocumentID: IntelTXTSpecificationDocumentID,
	}

	// TestsFIT exports the Slice with FIT tests
	TestsFIT = [...]*Test{
		&testfitvectorisset,
		&testhasfit,
		&testhasmcupdate,
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
		&testacmsfornpw,
		&testsinitacmupporttpm,
	}
)

// FITVectorIsSet checks if the FIT Vector is set
func FITVectorIsSet(txtAPI hwapi.APIInterfaces, config *tools.Configuration) (bool, error, error) {
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
		return false, fmt.Errorf("FitPointer must be in ValidFitRange"), nil
	}
	if fitPointer >= FITVector {
		return false, fmt.Errorf("FitPointer must be smaller than FITVector"), nil
	}

	return true, nil, nil
}

// HasFIT checks if the FIT is present
func HasFIT(txtAPI hwapi.APIInterfaces, config *tools.Configuration) (bool, error, error) {
	fithdr := make([]byte, 16)
	err := txtAPI.ReadPhysBuf(int64(fitPointer), fithdr)
	if err != nil {
		return false, nil, err
	}
	hdr, err := fit.ParseEntryHeadersFrom(bytes.NewReader(fithdr))
	if err != nil {
		return false, nil, err
	}

	if int64(fitPointer)+int64(hdr.DataSize()) > FourGiB {
		return false, fmt.Errorf("FIT isn't part of 32bit address-space"), nil
	}
	if int64(fitPointer)+int64(hdr.DataSize()) > FITVector {
		return false, fmt.Errorf("FIT isn't in the range (4 GB - 16 MB) to (4 GB - 40h)"), nil
	}

	fitblob := make([]byte, hdr.DataSize())
	err = txtAPI.ReadPhysBuf(int64(fitPointer), fitblob)

	fitHeaders, err = fit.ParseTable(fitblob)
	if err != nil {
		return false, nil, err
	}

	if fitHeaders == nil {
		return false, fmt.Errorf("FIT-Error: Referenz is nil"), nil
	}
	return true, nil, nil
}

// HasMicroCode checks if FIT table indicates a Microcode update for the CPU
func HasMicroCode(txtAPI hwapi.APIInterfaces, config *tools.Configuration) (bool, error, error) {
	for _, hdr := range fitHeaders {
		if hdr.Type() == fit.EntryTypeMicrocodeUpdateEntry {
			return true, nil, nil
		}
	}
	return false, fmt.Errorf("no microcode update entries found in FIT"), nil
}

// HasBIOSACM checks if FIT table has BIOSACM entry
func HasBIOSACM(txtAPI hwapi.APIInterfaces, config *tools.Configuration) (bool, error, error) {
	count := 0
	for _, hdr := range fitHeaders {
		if hdr.Type() == fit.EntryTypeStartupACModuleEntry {
			count++
		}
	}
	if count == 0 {
		return false, fmt.Errorf("FIT has no Startup AC Module Entry, but at least one is required"), nil
	}
	return true, nil, nil
}

// HasIBB checks if FIT table has BIOS Startup Module entry
func HasIBB(txtAPI hwapi.APIInterfaces, config *tools.Configuration) (bool, error, error) {
	for _, hdr := range fitHeaders {
		if hdr.Type() == fit.EntryTypeBIOSStartupModuleEntry {
			return true, nil, nil
		}
	}

	return false, fmt.Errorf("FIT has no BIOS Startup Module Entry, but at least one is required"), nil
}

// HasBIOSPolicy checks if FIT table has ONE BIOS Policy Data Record Entry
func HasBIOSPolicy(txtAPI hwapi.APIInterfaces, config *tools.Configuration) (bool, error, error) {
	if config.TXTMode == tools.AutoPromotion {
		return true, nil, nil
	}
	count := 0
	for _, hdr := range fitHeaders {
		if hdr.Type() == fit.EntryTypeBIOSPolicyRecord {
			count++
		}
	}
	if count == 0 {
		return false, fmt.Errorf("FIT has no BIOS Policy Data Record Entry - See Intel Firmware Interface Table BIOS Specification Document Number: 338505-001, P. 11"), nil
	}

	if count > 1 {
		return false, fmt.Errorf("FIT has more than 1 BIOS Policy Data Record Entry, only one is allowed - See Intel Firmware Interface Table BIOS Specification Document Number: 338505-001, P. 11"), nil
	}
	return true, nil, nil
}

// IBBCoversResetVector checks if BIOS Startup Module Entry covers Reset Vector
func IBBCoversResetVector(txtAPI hwapi.APIInterfaces, config *tools.Configuration) (bool, error, error) {
	for _, hdr := range fitHeaders {
		if hdr.Type() == fit.EntryTypeBIOSStartupModuleEntry {
			addr := hdr.Address.Pointer()
			coversRv := addr <= ResetVector && addr+uint64(hdr.DataSize()) >= ResetVector+4

			if coversRv {
				return true, nil, nil
			}
		}
	}

	return false, fmt.Errorf("BIOS Startup Module Entry must cover Reset Vector"), nil
}

// IBBCoversFITVector checks if BIOS Startup Module Entry covers FIT vector
func IBBCoversFITVector(txtAPI hwapi.APIInterfaces, config *tools.Configuration) (bool, error, error) {
	for _, hdr := range fitHeaders {
		if hdr.Type() == fit.EntryTypeBIOSStartupModuleEntry {
			addr := hdr.Address.Pointer()
			coversRv := addr <= FITVector && addr+uint64(hdr.DataSize()) >= FITVector+4
			if coversRv {
				return true, nil, nil
			}
		}
	}

	return false, fmt.Errorf("BIOS Startup Module Entry must cover Firmware Interface Table Vector"), nil
}

// IBBCoversFIT checks if BIOS Startup Module Entry covers FIT table
func IBBCoversFIT(txtAPI hwapi.APIInterfaces, config *tools.Configuration) (bool, error, error) {
	for _, hdr := range fitHeaders {
		if hdr.Type() == fit.EntryTypeBIOSStartupModuleEntry {
			addr := hdr.Address.Pointer()
			coversRv := addr <= uint64(fitPointer) && addr+uint64(hdr.DataSize()) >= uint64(fitPointer+uint32(len(fitHeaders)*16))

			if coversRv {
				return true, nil, nil
			}
		}
	}

	return false, fmt.Errorf("BIOS Startup Module Entry must cover Firmware Interface Table"), nil
}

// NoIBBOverlap checks if BIOS Startup Module Entries overlap
func NoIBBOverlap(txtAPI hwapi.APIInterfaces, config *tools.Configuration) (bool, error, error) {
	for i, hdr1 := range fitHeaders {
		if hdr1.Type() == fit.EntryTypeBIOSStartupModuleEntry {
			for j, hdr2 := range fitHeaders {
				if i < j && hdr2.Type() == fit.EntryTypeBIOSStartupModuleEntry {
					a := hdr1.Address.Pointer() > hdr2.Address.Pointer()+uint64(hdr2.DataSize())
					b := hdr2.Address.Pointer() > hdr1.Address.Pointer()+uint64(hdr1.DataSize())

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
func NoBIOSACMOverlap(txtAPI hwapi.APIInterfaces, config *tools.Configuration) (bool, error, error) {
	for i, hdr1 := range fitHeaders {
		if hdr1.Type() == fit.EntryTypeBIOSStartupModuleEntry {
			for j, hdr2 := range fitHeaders {
				if i < j && hdr2.Type() == fit.EntryTypeStartupACModuleEntry {
					a := hdr1.Address.Pointer() > hdr2.Address.Pointer()+uint64(hdr2.DataSize())
					b := hdr2.Address.Pointer() > hdr1.Address.Pointer()+uint64(hdr1.DataSize())

					if !a && !b {
						return false, fmt.Errorf("startup AC Module Entries overlap"), nil
					}
				}
			}
		}
	}

	return true, nil, nil
}

// BIOSACMIsBelow4G checks if BIOS ACM is below 4Gb (has a valid address)
func BIOSACMIsBelow4G(txtAPI hwapi.APIInterfaces, config *tools.Configuration) (bool, error, error) {
	for _, hdr := range fitHeaders {
		if hdr.Type() == fit.EntryTypeStartupACModuleEntry {
			if hdr.Address.Pointer()+uint64(hdr.DataSize()) > uint64(FourGiB) {
				return false, fmt.Errorf("startup AC Module Entry is above 4Gib"), nil
			}
		}
	}

	return true, nil, nil
}

// PolicyAllowsTXT checks if Record matches TXT requirements.
func PolicyAllowsTXT(txtAPI hwapi.APIInterfaces, config *tools.Configuration) (bool, error, error) {
	for _, hdr := range fitHeaders {
		if hdr.Type() == fit.EntryTypeTXTPolicyRecord {
			switch hdr.Version {
			case 0:
				return false, nil, fmt.Errorf("indexed IO type pointer are not supported")
			case 1:
				var b hwapi.Uint8

				err := txtAPI.ReadPhys(int64(hdr.Address), &b)
				if err != nil {
					return false, nil, err
				}

				return b&1 != 0, nil, nil
			default:
				return false, fmt.Errorf("unknown TXT policy record version %d - See Intel Firmware Interface Table BIOS Specification Document Number: 338505-001, P. 11", hdr.Version), nil
			}
		}
	}

	// No record means TXT is enabled
	return true, nil, nil
}

// BIOSACMValid checks if BIOS ACM is valid
func BIOSACMValid(txtAPI hwapi.APIInterfaces, _ *tools.Configuration) (bool, error, error) {
	acm, _, _, _, err, internalerr := biosACM(txtAPI, fitHeaders)

	return acm != nil, err, internalerr
}

// BIOSACMSizeCorrect checks if BIOS ACM size is correct
func BIOSACMSizeCorrect(txtAPI hwapi.APIInterfaces, _ *tools.Configuration) (bool, error, error) {
	acm, _, _, _, err, internalerr := biosACM(txtAPI, fitHeaders)
	if internalerr != nil {
		return false, nil, internalerr
	}
	if err != nil {
		return false, err, nil
	}

	if acm.Header.Size%64 != 0 {
		return false, fmt.Errorf("BIOSACM Size is not correct "), nil
	}
	return true, nil, nil
}

// BIOSACMAlignmentCorrect checks if BIOS ACM alignment is correct
func BIOSACMAlignmentCorrect(txtAPI hwapi.APIInterfaces, _ *tools.Configuration) (bool, error, error) {
	for _, hdr := range fitHeaders {
		if hdr.Type() == fit.EntryTypeStartupACModuleEntry {
			buf1 := make([]byte, tools.ACMheaderLen*4)

			err := txtAPI.ReadPhysBuf(int64(hdr.Address.Pointer()), buf1)

			if err != nil {
				return false, nil, fmt.Errorf("ReadPhysBuf failed at %v with error: %v", hdr.Address.Pointer(), err)
			}

			acm, err := tools.ParseACMHeader(buf1)
			if err != nil {
				return false, nil, fmt.Errorf("can't Parse BIOS ACM header correctly")
			}

			ret, err := tools.ValidateACMHeader(acm)

			if ret == false {
				return false, nil, fmt.Errorf("validating BIOS ACM Header failed: %v", err)
			}

			size := uint64(math.Pow(2, math.Ceil(math.Log(float64(acm.Size*4))/math.Log(2))))
			if hdr.Address.Pointer()&(size-1) > 0 {
				return false, fmt.Errorf("BIOSACM not aligned at %x", size), nil
			}
		}
	}

	return true, nil, nil
}

// BIOSACMMatchesChipset checks if BIOS ACM matches chipset
func BIOSACMMatchesChipset(txtAPI hwapi.APIInterfaces, config *tools.Configuration) (bool, error, error) {
	_, chp, _, _, err, internalerr := biosACM(txtAPI, fitHeaders)
	if internalerr != nil {
		return false, nil, internalerr
	}
	if err != nil {
		return false, err, nil
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
func BIOSACMMatchesCPU(txtAPI hwapi.APIInterfaces, config *tools.Configuration) (bool, error, error) {
	_, _, cpus, _, err, internalerr := biosACM(txtAPI, fitHeaders)
	if internalerr != nil {
		return false, nil, internalerr
	}
	if err != nil {
		return false, err, nil
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

func biosACM(txtAPI hwapi.APIInterfaces, fitHeaders fit.Table) (*tools.ACM, *tools.Chipsets, *tools.Processors, *tools.TPMs, error, error) {
	for _, hdr := range fitHeaders {
		if hdr.Type() == fit.EntryTypeStartupACModuleEntry {
			buf1 := make([]byte, tools.ACMheaderLen*4)

			err := txtAPI.ReadPhysBuf(int64(hdr.Address), buf1)

			if err != nil {
				return nil, nil, nil, nil, nil, fmt.Errorf("ReadPhysBuf failed at %v with error: %v", hdr.Address, err)
			}

			acm, err := tools.ParseACMHeader(buf1)
			if err != nil {
				return nil, nil, nil, nil, fmt.Errorf("cannot Parse BIOS ACM header correctly"), nil
			}

			ret, err := tools.ValidateACMHeader(acm)

			if ret == false {
				return nil, nil, nil, nil, fmt.Errorf("validating BIOS ACM Header failed: %v", err), nil
			}

			buf2 := make([]byte, acm.Size*4)
			err = txtAPI.ReadPhysBuf(int64(hdr.Address), buf2)

			if err != nil {
				return nil, nil, nil, nil, nil, fmt.Errorf("cannot read BIOS ACM completly")
			}

			return tools.ParseACM(buf2)
		}
	}

	return nil, nil, nil, nil, fmt.Errorf("no BIOS ACM in FIT"), nil
}

// SINITandBIOSACMnoNPW checks that in BIOS integrated ACMs (SINIT, BIOS) are production worthy
func SINITandBIOSACMnoNPW(txtAPI hwapi.APIInterfaces, config *tools.Configuration) (bool, error, error) {
	biosACMs, _, _, _, err, internalerr := biosACM(txtAPI, fitHeaders)
	if internalerr != nil {
		return false, nil, internalerr
	}
	if err != nil {
		return false, err, nil
	}
	biosACMFlags := biosACMs.Header.ParseACMFlags()
	if biosACMFlags.PreProduction || biosACMFlags.DebugSigned {
		return false, fmt.Errorf("BIOS ACM is either debug signed or NPW"), nil
	}
	buf, err := tools.FetchTXTRegs(txtAPI)
	if err != nil {
		return false, nil, err
	}
	regs, err := tools.ParseTXTRegs(buf)
	if err != nil {
		return false, nil, err
	}
	sinitACMs, _, _, _, err, internalerr := sinitACM(txtAPI, regs)
	if internalerr != nil {
		return false, nil, internalerr
	}
	if err != nil {
		return false, err, nil
	}
	sinitACMFlags := sinitACMs.Header.ParseACMFlags()
	if sinitACMFlags.PreProduction || sinitACMFlags.DebugSigned {
		return false, fmt.Errorf("SINIT ACM is either debug signed or NPW"), nil
	}
	return true, nil, nil
}

// SINITACMcomplyTPMSpec tests if the SINIT ACM complys with used TPM
func SINITACMcomplyTPMSpec(txtAPI hwapi.APIInterfaces, config *tools.Configuration) (bool, error, error) {
	buf, err := tools.FetchTXTRegs(txtAPI)
	if err != nil {
		return false, nil, err
	}
	regs, err := tools.ParseTXTRegs(buf)
	if err != nil {
		return false, nil, err
	}
	_, _, _, tpms, err, internalerr := sinitACM(txtAPI, regs)
	if internalerr != nil {
		return false, nil, internalerr
	}
	if err != nil {
		return false, err, nil
	}
	res := (1 >> tpms.Capabilities & (uint32(tools.TPMFamilyDTPM12) | uint32(tools.TPMFamilyDTPMBoth)))
	if res == 0 && config.TPM == hwapi.TPMVersion12 && testtpmispresent.Result == ResultPass {
		return true, nil, nil
	}
	res = (1 >> tpms.Capabilities & (uint32(tools.TPMFamilyDTPM20) | uint32(tools.TPMFamilyDTPMBoth)))
	if res == 0 && config.TPM == hwapi.TPMVersion20 && testtpmispresent.Result == ResultPass {
		return true, nil, nil
	}
	return false, fmt.Errorf("SINIT ACM does not support used TPM"), nil
}
