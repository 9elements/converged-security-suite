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
		Name:         "initial bootblock entry in FIT",
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
		Name:         "Initial bootblock covers reset vector",
		Required:     true,
		function:     TestIBBCoversResetVector,
		dependencies: []*Test{&testhasfit, &testhasibb},
		Status:       TestImplemented,
	}
	testibbcoversfitvector = Test{
		Name:         "Initial bootblock covers FIT vector",
		Required:     true,
		function:     TestIBBCoversFITVector,
		dependencies: []*Test{&testhasfit, &testhasibb},
		Status:       TestImplemented,
	}
	testibbcoversfit = Test{
		Name:         "Initial bootblock covers FIT",
		Required:     true,
		function:     TestIBBCoversFIT,
		dependencies: []*Test{&testhasfit, &testhasibb},
		Status:       TestImplemented,
	}
	testnoibboverlap = Test{
		Name:         "Initial bootblock does not overlap",
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
		Name:         "Initial bootblock and BIOS ACM below 4GiB",
		Required:     true,
		function:     TestBIOSACMIsBelow4G,
		dependencies: []*Test{&testhasfit, &testhasbiosacm},
		Status:       TestImplemented,
	}
	testpolicyallowstxt = Test{
		Name:         "Intel TXT not disabled by LCP Policy",
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

	if fitPointer < 0xff000000 || fitPointer >= ResetVector {
		return false, nil
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

	if int64(fitPointer)+int64(hdr.Size()) > 0x100000000 {
		return false, fmt.Errorf("FIT isn't part of 32bit address-space")
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

	return count == 1, nil
}

func TestHasIBB() (bool, error) {
	for _, ent := range fit {
		if ent.Type() == api.BIOSStartUpMod {
			return true, nil
		}
	}

	return false, nil
}

func TestHasBIOSPolicy() (bool, error) {
	count := 0
	for _, ent := range fit {
		if ent.Type() == api.BIOSPolicyRec {
			count += 1
		}
	}

	return count == 1, nil
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

	return false, nil
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

	return false, nil
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

	return false, nil
}

func TestNoIBBOverlap() (bool, error) {
	for i, ent1 := range fit {
		if ent1.Type() == api.BIOSStartUpMod {
			for j, ent2 := range fit {
				if i < j && ent2.Type() == api.BIOSStartUpMod {
					a := ent1.Address > ent2.Address+uint64(ent2.Size())
					b := ent2.Address > ent1.Address+uint64(ent1.Size())

					if !a && !b {
						return false, nil
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
						return false, nil
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
				return false, nil
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
				return false, fmt.Errorf("Indexed IO type pointer are not supported")
			case 1:
				var b api.Uint8

				err := api.ReadPhys(int64(ent.Address), &b)
				if err != nil {
					return false, err
				}

				return b&1 != 0, nil
			default:
				return false, fmt.Errorf("Unknown TXT policy record version %d", ent.Version)
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

	return acm.HeaderLen%64 == 0, nil
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

	txt, err := api.ReadTXTRegs()
	if err != nil {
		return false, err
	}

	for _, ch := range chp.IDList {
		a := ch.VendorID == txt.Vid
		b := ch.DeviceID == txt.Did

		if a && b {
			if acm.Flags&1 != 0 {
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

	return false, nil
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

	return false, nil
}

func biosACM(fit []api.FitEntry) (*api.ACM, *api.Chipsets, *api.Processors, *api.TPMs, error) {
	for _, ent := range fit {
		if ent.Type() == api.StartUpACMod {
			buf := make([]byte, 224*4)

			err := api.ReadPhysBuf(int64(ent.Address), buf)
			if err != nil {
				return nil, nil, nil, nil, err
			}

			return api.ParseACM(buf)
		}
	}

	return nil, nil, nil, nil, fmt.Errorf("no BIOS ACM in FIT")
}
