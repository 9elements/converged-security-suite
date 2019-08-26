package test

import (
	"bytes"
	"encoding/binary"
	"fmt"

	"github.com/9elements/txt-suite/pkg/api"
)

// 16MiB
const FITSize int64 = 16 * 1024 * 1024
const FourGiB int64 = 0x100000000
const ResetVector = 0xFFFFFFF0
const FITVector = 0xFFFFFFC0
const ACMheaderLegSize = uint32(4 * 161)
const ValidFitRange = 0xFF000000


var (
	fitImage []byte
	// set by FITVectorIsSet
	fitPointer uint32
	// set by testhasfit
	fit []api.FitEntry

	testfitvectorisset = Test{
		Name:     "Valid FIT vector",
		Required: true,
		function: FITVectorIsSet,
		Status:   TestImplemented,
	}
	testhasfit = Test{
		Name:         "Valid FIT",
		Required:     true,
		function:     TestHasFIT,
		dependencies: []*Test{&testfitvectorisset},
		Status:       TestImplemented,
	}
	testhasbiosacm = Test{
		Name:         "BIOS ACM entry in FIT",
		Required:     true,
		function:     TestHasBIOSACM,
		dependencies: []*Test{&testhasfit},
		Status:       TestImplemented,
	}
	testhasibb = Test{
		Name:         "IBB entry in FIT",
		Required:     true,
		function:     TestHasIBB,
		dependencies: []*Test{&testhasfit},
		Status:       TestImplemented,
	}
	// Not mandatory, LCP_POLICY_DATA file may be supplied by GRUB to TBOOT
	testhaslcpTest = Test{
		Name:         "LCP Policy entry in FIT",
		Required:     false,
		function:     TestHasBIOSPolicy,
		dependencies: []*Test{&testhasfit},
		Status:       TestImplemented,
	}
	testibbcoversresetvector = Test{
		Name:         "IBB covers reset vector",
		Required:     true,
		function:     TestIBBCoversResetVector,
		dependencies: []*Test{&testhasfit, &testhasibb},
		Status:       TestImplemented,
	}
	testibbcoversfitvector = Test{
		Name:         "IBB covers FIT vector",
		Required:     true,
		function:     TestIBBCoversFITVector,
		dependencies: []*Test{&testhasfit, &testhasibb},
		Status:       TestImplemented,
	}
	testibbcoversfit = Test{
		Name:         "IBB covers FIT",
		Required:     true,
		function:     TestIBBCoversFIT,
		dependencies: []*Test{&testhasfit, &testhasibb},
		Status:       TestImplemented,
	}
	testnoibboverlap = Test{
		Name:         "IBB does not overlap",
		Required:     true,
		function:     TestNoIBBOverlap,
		dependencies: []*Test{&testhasfit, &testhasibb},
		Status:       TestImplemented,
	}
	testnobiosacmoverlap = Test{
		Name:         "BIOS ACM does not overlap",
		Required:     true,
		function:     TestNoBIOSACMOverlap,
		dependencies: []*Test{&testhasfit, &testhasbiosacm},
		Status:       TestImplemented,
	}
	testnobiosacmisbelow4g = Test{
		Name:         "IBB and BIOS ACM below 4GiB",
		Required:     true,
		function:     TestBIOSACMIsBelow4G,
		dependencies: []*Test{&testhasfit, &testhasbiosacm},
		Status:       TestImplemented,
	}
	testpolicyallowstxt = Test{
		Name:         "TXT not disabled by LCP Policy",
		Required:     true,
		function:     TestPolicyAllowsTXT,
		dependencies: []*Test{&testhasfit},
		Status:       TestImplemented,
	}
	testbiosacmvalid = Test{
		Name:         "BIOSACM header valid",
		Required:     true,
		function:     TestBIOSACMValid,
		dependencies: []*Test{&testhasfit, &testhasbiosacm},
		Status:       TestImplemented,
	}
	testbiosacmsizecorrect = Test{
		Name:         "BIOSACM size check",
		Required:     true,
		function:     TestBIOSACMSizeCorrect,
		dependencies: []*Test{&testhasfit, &testhasbiosacm},
		Status:       TestImplemented,
	}
	testbiosacmaligmentcorrect = Test{
		Name:         "BIOSACM alignment check",
		Required:     true,
		function:     TestBIOSACMAlignmentCorrect,
		dependencies: []*Test{&testhasfit, &testhasbiosacm},
		Status:       TestImplemented,
	}
	testbiosacmmatcheschipset = Test{
		Name:         "BIOSACM matches chipset",
		Required:     true,
		function:     TestBIOSACMMatchesChipset,
		dependencies: []*Test{&testhasfit, &testhasbiosacm},
		Status:       TestImplemented,
	}
	testbiosacmmatchescpu = Test{
		Name:         "BIOSACM matches processor",
		Required:     true,
		function:     TestBIOSACMMatchesCPU,
		dependencies: []*Test{&testhasfit, &testhasbiosacm},
		Status:       TestImplemented,
	}
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

/*
func LoadFITFromFile(path string) error {
	fd, err := os.Open(path)
	if err != nil {
		return err
	}

	defer fd.Close()

	fitImage = make([]byte, FITSize)
	_, err = fd.ReadAt(fitImage, FourGiB-FITSize)
	if err != nil {
		return err
	}

	return nil
} */

func FITVectorIsSet() (bool, error) {
	fitvec := make([]byte, 4)
	err := api.ReadPhysBuf(FITVector, fitvec)

	if err != nil {
		return false, err
	}

	buf := bytes.NewReader(fitvec)
	err = binary.Read(buf, binary.LittleEndian, &fitPointer)
	if err != nil {
		return false, err
	}

	if fitPointer < ValidFitRange {
		return false, fmt.Errorf("FitPointer must be in ValidFitRange - See Intel Firmware Interface Table BIOS Specification Document Number: 338505-001, P. 6")
	}
	if fitPointer >= ResetVector {
		return false, fmt.Errorf("FitPointer must be smaller than ResetVector - See Intel Firmware Interface Table BIOS Specification Document Number: 338505-001, P. 6")
	}

	return true, nil
}

func TestHasFIT() (bool, error) {
	fithdr := make([]byte, 16)
	err := api.ReadPhysBuf(int64(fitPointer), fithdr)
	if err != nil {
		return false, err
	}

	hdr, err := api.GetFitHeader(fithdr)
	if err != nil {
		return false, err
	}

	if int64(fitPointer)+int64(hdr.Size()) > FourGiB {
		return false, fmt.Errorf("FIT isn't part of 32bit address-space - See Intel Firmware Interface Table BIOS Specification Document Number: 338505-001, P. 6")
	}

	fitblob := make([]byte, hdr.Size())
	err = api.ReadPhysBuf(int64(fitPointer), fitblob)

	fit, err = api.ExtractFit(fitblob)
	if err != nil {
		return false, err
	}

	if fit == nil {
		return false, nil
	}
	return true, nil
}

func TestHasBIOSACM() (bool, error) {
	count := 0
	for _, ent := range fit {
		if ent.Type() == api.StartUpACMod {
			count += 1
		}
	}
	if count == 0 {
		return false, fmt.Errorf("Fit has no Startup AC Module Entry, but at least one is required - See Intel Firmware Interface Table BIOS Specification Document Number: 338505-001, P. 9")
	}
	return true, nil
}

func TestHasIBB() (bool, error) {
	for _, ent := range fit {
		if ent.Type() == api.BIOSStartUpMod {
			return true, nil
		}
	}

	return false, fmt.Errorf("Fit has no BIOS Startup Module Entry, but at least one is required - See Intel Firmware Interface Table BIOS Specification Document Number: 338505-001, P. 10")
}

func TestHasBIOSPolicy() (bool, error) {
	count := 0
	for _, ent := range fit {
		if ent.Type() == api.BIOSPolicyRec {
			count += 1
		}
	}
	if count == 0 {
		return false, fmt.Errorf("Fit has no BIOS Policy Data Record Entry - See Intel Firmware Interface Table BIOS Specification Document Number: 338505-001, P. 11")
	}

	if count > 1 {
		return false, fmt.Errorf("Fit has more than 1 BIOS Policy Data Record Entry, only one is allowed - See Intel Firmware Interface Table BIOS Specification Document Number: 338505-001, P. 11")
	}
	return true, nil
}

func TestIBBCoversResetVector() (bool, error) {
	for _, ent := range fit {
		if ent.Type() == api.BIOSStartUpMod {
			coversRv := ent.Address <= ResetVector && ent.Address+uint64(ent.Size()) >= ResetVector+4

			if coversRv {
				return true, nil
			}
		}
	}

	return false, fmt.Errorf("BIOS Startup Module Entry must cover Reset Vector")
}

func TestIBBCoversFITVector() (bool, error) {
	for _, ent := range fit {
		if ent.Type() == api.BIOSStartUpMod {
			coversRv := ent.Address <= FITVector && ent.Address+uint64(ent.Size()) >= FITVector+4

			if coversRv {
				return true, nil
			}
		}
	}

	return false, fmt.Errorf("BIOS Startup Module Entry must cover Firmware Interface Table Vector")
}

func TestIBBCoversFIT() (bool, error) {
	for _, ent := range fit {
		if ent.Type() == api.BIOSStartUpMod {
			coversRv := ent.Address <= uint64(fitPointer) && ent.Address+uint64(ent.Size()) >= uint64(fitPointer+uint32(len(fit)*16))

			if coversRv {
				return true, nil
			}
		}
	}

	return false, fmt.Errorf("BIOS Startup Module Entry must cover Firmware Interface Table")
}

func TestNoIBBOverlap() (bool, error) {
	for i, ent1 := range fit {
		if ent1.Type() == api.BIOSStartUpMod {
			for j, ent2 := range fit {
				if i < j && ent2.Type() == api.BIOSStartUpMod {
					a := ent1.Address > ent2.Address+uint64(ent2.Size())
					b := ent2.Address > ent1.Address+uint64(ent1.Size())

					if !a && !b {
						return false, fmt.Errorf("BIOS Startup Module Entries overlap ")
					}
				}
			}
		}
	}

	return true, nil
}

func TestNoBIOSACMOverlap() (bool, error) {
	for i, ent1 := range fit {
		if ent1.Type() == api.BIOSStartUpMod {
			for j, ent2 := range fit {
				if i < j && ent2.Type() == api.StartUpACMod {
					a := ent1.Address > ent2.Address+uint64(ent2.Size())
					b := ent2.Address > ent1.Address+uint64(ent1.Size())

					if !a && !b {
						return false, fmt.Errorf("Startup AC Module Entries overlap")
					}
				}
			}
		}
	}

	return true, nil
}

func TestBIOSACMIsBelow4G() (bool, error) {
	for _, ent := range fit {
		if ent.Type() == api.StartUpACMod {
			if ent.Address+uint64(ent.Size()) > uint64(FourGiB) {
				return false, fmt.Errorf("Startup AC Module Entry is above 4Gib")
			}
		}
	}

	return true, nil
}

func TestPolicyAllowsTXT() (bool, error) {
	for _, ent := range fit {
		if ent.Type() == api.TXTPolicyRec {
			switch ent.Version {
			case 0:
				return false, fmt.Errorf("Indexed IO type pointer are not supported - See Intel Firmware Interface Table BIOS Specification Document Number: 338505-001, P. 11")
			case 1:
				var b api.Uint8

				err := api.ReadPhys(int64(ent.Address), &b)
				if err != nil {
					return false, err
				}

				return b&1 != 0, nil
			default:
				return false, fmt.Errorf("Unknown TXT policy record version %d - See Intel Firmware Interface Table BIOS Specification Document Number: 338505-001, P. 11", ent.Version)
			}
		}
	}

	// No record means TXT is enabled
	return true, nil
}

func TestBIOSACMValid() (bool, error) {
	acm, _, _, _, err := biosACM(fit)

	return acm != nil, err
}

func TestBIOSACMSizeCorrect() (bool, error) {
	acm, _, _, _, err := biosACM(fit)
	if err != nil {
		return false, err
	}

	if acm.HeaderLen%64 != 0 {
		return false, fmt.Errorf("BIOSACM Size is not correct ")
	}
	return true, nil

}

func TestBIOSACMAlignmentCorrect() (bool, error) {
	for _, ent := range fit {
		if ent.Type() == api.StartUpACMod {
			return ent.Address%(128*1024) == 0, nil
		}
	}

	return false, fmt.Errorf("no BIOS ACM in FIT")
}

func TestBIOSACMMatchesChipset() (bool, error) {
	acm, chp, _, _, err := biosACM(fit)
	if err != nil {
		return false, err
	}
	buf, err := api.FetchTXTRegs()
	if err != nil {
		return false, err
	}
	txt, err := api.ParseTXTRegs(buf)
	if err != nil {
		return false, err
	}

	for _, ch := range chp.IDList {
		a := ch.VendorID == txt.Vid
		b := ch.DeviceID == txt.Did

		if a && b {
			if acm.Header.Flags&1 != 0 {
				if ch.RevisionID&txt.Rid == txt.Rid {
					return true, nil
				}
			} else {
				if ch.RevisionID == txt.Rid {
					return true, nil
				}
			}
		}
	}

	return false, fmt.Errorf("BIOS StartUp Module and Chipset doens't match")
}

func TestBIOSACMMatchesCPU() (bool, error) {
	_, _, cpus, _, err := biosACM(fit)
	if err != nil {
		return false, err
	}

	// IA32_PLATFORM_ID
	platform, err := api.IA32PlatformID()
	if err != nil {
		return false, err
	}

	fms := api.CPUSignature()

	for _, cpu := range cpus.IDList {
		a := fms&cpu.FMSMask == cpu.FMS
		b := platform&cpu.PlatformMask == cpu.PlatformID

		if a && b {
			return true, nil
		}
	}

	return false, fmt.Errorf("BIOS Startup Module and CPU doesn't match")
}

func biosACM(fit []api.FitEntry) (*api.ACM, *api.Chipsets, *api.Processors, *api.TPMs, error) {
	for _, ent := range fit {
		if ent.Type() == api.StartUpACMod {
			buf1 := make([]byte, ACMheaderLegSize)

			err := api.ReadPhysBuf(int64(ent.Address), buf1)

			if err != nil {
				return nil, nil, nil, nil, fmt.Errorf("ReadPhysBuf failed at %v with error: %v", ent.Address, err)
			}

			acm, err := api.ParseACMHeader(buf1)
			if err != nil {
				return nil, nil, nil, nil, fmt.Errorf("Can't Parse BIOS ACM header correctly")
			}

			ret, err := api.ValidateACMHeader(acm)

			if ret == false {
				return nil, nil, nil, nil, fmt.Errorf("Validating BIOS ACM Header failed: %v", err)
			}

			buf2 := make([]byte, acm.Size)
			err = api.ReadPhysBuf(int64(ent.Address), buf2)

			if err != nil {
				return nil, nil, nil, nil, fmt.Errorf("Cant read BIOS ACM completly")
			}

			return api.ParseACM(buf2)
		}
	}

	return nil, nil, nil, nil, fmt.Errorf("no BIOS ACM in FIT")
}
