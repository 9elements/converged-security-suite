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
	// set by test22hasfit
	fit []api.FitEntry

	testfitvectorisset = Test{
		Name:     "Has valid FIT vector",
		Required: true,
		function: FITVectorIsSet,
	}
	test22hasfit = Test{
		Name:         "Has valid FIT",
		Required:     true,
		function:     Test22HasFIT,
		dependencies: []*Test{&testfitvectorisset},
	}
	test23hasbiosacm = Test{
		Name:         "FIT has an BIOS ACM entry",
		Required:     true,
		function:     Test23HasBIOSACM,
		dependencies: []*Test{&test22hasfit},
	}
	test24hasibb = Test{
		Name:         "FIT has a initial bootblock entry",
		Required:     true,
		function:     Test24HasIBB,
		dependencies: []*Test{&test22hasfit},
	}
	test25haslcpTest = Test{
		Name:         "FIT has a LCP Policy entry. Not mandatory, LCP_POLICY_DATA file may be supplied by GRUB to TBOOT",
		Required:     false,
		function:     Test25HasBIOSPolicy,
		dependencies: []*Test{&test22hasfit},
	}
	test26ibbcoversresetvector = Test{
		Name:         "Initial bootblock covers reset vector",
		Required:     true,
		function:     Test26IBBCoversResetVector,
		dependencies: []*Test{&test22hasfit, &test24hasibb},
	}
	ibbcoversfitvector = Test{
		Name:         "Initial bootblock covers FIT vector",
		Required:     true,
		function:     IBBCoversFITVector,
		dependencies: []*Test{&test22hasfit, &test24hasibb},
	}
	ibbcoversfit = Test{
		Name:         "Initial bootblock covers FIT",
		Required:     true,
		function:     IBBCoversFIT,
		dependencies: []*Test{&test22hasfit, &test24hasibb},
	}
	test27noibboverlap = Test{
		Name:         "Initial bootblock does not overlap",
		Required:     true,
		function:     Test27NoIBBOverlap,
		dependencies: []*Test{&test22hasfit, &test24hasibb},
	}
	test28nobiosacmoverlap = Test{
		Name:         "BIOS ACM does not overlap",
		Required:     true,
		function:     Test28NoBIOSACMOverlap,
		dependencies: []*Test{&test22hasfit, &test23hasbiosacm},
	}
	test29nobiosacmisbelow4g = Test{
		Name:         "Initial bootblock and BIOS ACM is below 4GiB",
		Required:     true,
		function:     Test29BIOSACMIsBelow4G,
		dependencies: []*Test{&test22hasfit, &test23hasbiosacm},
	}
	test30policyallowstxt = Test{
		Name:         "LCP Policy does not disable Intel TXT",
		Required:     true,
		function:     Test30PolicyAllowsTXT,
		dependencies: []*Test{&test22hasfit},
	}
	TestsFIT = [...]*Test{
		&testfitvectorisset,
		&test22hasfit,
		&test23hasbiosacm,
		&test24hasibb,
		&test25haslcpTest,
		&test26ibbcoversresetvector,
		&ibbcoversfitvector,
		&ibbcoversfit,
		&test27noibboverlap,
		&test28nobiosacmoverlap,
		&test29nobiosacmisbelow4g,
		&test30policyallowstxt,
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

func Test22HasFIT() (bool, error) {
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

func Test23HasBIOSACM() (bool, error) {
	count := 0
	for _, ent := range fit {
		if ent.Type() == api.StartUpACMod {
			count += 1
		}
	}

	return count == 1, nil
}

func Test24HasIBB() (bool, error) {
	for _, ent := range fit {
		if ent.Type() == api.BIOSStartUpMod {
			return true, nil
		}
	}

	return false, nil
}

func Test25HasBIOSPolicy() (bool, error) {
	count := 0
	for _, ent := range fit {
		if ent.Type() == api.BIOSPolicyRec {
			count += 1
		}
	}

	return count == 1, nil
}

func Test26IBBCoversResetVector() (bool, error) {
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

func IBBCoversFITVector() (bool, error) {
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

func IBBCoversFIT() (bool, error) {
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

func Test27NoIBBOverlap() (bool, error) {
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

func Test28NoBIOSACMOverlap() (bool, error) {
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

func Test29BIOSACMIsBelow4G() (bool, error) {
	for _, ent := range fit {
		if ent.Type() == api.StartUpACMod {
			if ent.Address+uint64(ent.Size()) > uint64(FourGiB) {
				return false, nil
			}
		}
	}

	return true, nil
}

func Test30PolicyAllowsTXT() (bool, error) {
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

func Test31BIOSACMValid() (bool, error) {
	acm, _, _, _, err := biosACM(fit)

	return acm != nil, err
}

func Test32BIOSACMSizeCorrect() (bool, error) {
	acm, _, _, _, err := biosACM(fit)
	if err != nil {
		return false, err
	}

	return acm.HeaderLen%64 == 0, nil
}

func Test33BIOSACMAlignmentCorrect() (bool, error) {
	for _, ent := range fit {
		if ent.Type() == api.StartUpACMod {
			return ent.Address%(128*1024) == 0, nil
		}
	}

	return false, fmt.Errorf("no BIOS ACM in FIT")
}

func Test34BIOSACMMatchesChipset() (bool, error) {
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

func Test35BIOSACMMatchesCPU() (bool, error) {
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
