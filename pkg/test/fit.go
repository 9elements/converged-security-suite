package test

import (
	"fmt"
	"os"

	"github.com/9elements/txt-suite/pkg/api"
)

// 16MiB
const FITSize int64 = 16 * 1024 * 1024
const FourGiB int64 = 0x100000000

var (
	fitImage []byte
	TestsFIT = [...]Test{
		Test{
			name:     "Has FIT",
			required: true,
			function: Test22HasFIT,
		},
		Test{
			name:     "FIT has an BIOS ACM entry",
			required: true,
			function: Test23HasBIOSACM,
		},
		Test{
			name:     "FIT has a initial bootblock entry",
			required: true,
			function: Test24HasIBB,
		},
		Test{
			name:     "FIT has a LCP Policy entry",
			required: true,
			function: Test25HasBIOSPolicy,
		},
		Test{
			name:     "Initial bootblock covers reset vector",
			required: true,
			function: Test26IBBCoversResetVector,
		},
		Test{
			name:     "Initial bootblock does not overlap",
			required: true,
			function: Test27NoIBBOverlap,
		},
		Test{
			name:     "BIOS ACM does not overlap",
			required: true,
			function: Test28NoBIOSACMOverlap,
		},
		Test{
			name:     "Initial bootblock and BIOS ACM is below 4GiB",
			required: true,
			function: Test29BIOSACMIsAbove4G,
		},
		Test{
			name:     "LCP Policy does not disable Intel TXT",
			required: true,
			function: Test30PolicyAllowsTXT,
		},
	}
)

func LoadFITFromMemory() error {
	var buf api.Uint8

	for i := int64(0); i < FITSize; i += 1 {
		err := api.ReadPhys(FourGiB-FITSize+i, &buf)
		if err != nil {
			return err
		}

		fitImage = append(fitImage, byte(buf))
	}

	return nil
}

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
}

func Test22HasFIT() (bool, error) {
	if len(fitImage) == 0 {
		return false, fmt.Errorf("No FIT image loaded")
	}

	return false, fmt.Errorf("Unimplemented")
}

func Test23HasBIOSACM() (bool, error) {
	if len(fitImage) == 0 {
		return false, fmt.Errorf("No FIT image loaded")
	}
	return false, fmt.Errorf("Unimplemented")
}

func Test24HasIBB() (bool, error) {
	if len(fitImage) == 0 {
		return false, fmt.Errorf("No FIT image loaded")
	}
	return false, fmt.Errorf("Unimplemented")
}

func Test25HasBIOSPolicy() (bool, error) {
	if len(fitImage) == 0 {
		return false, fmt.Errorf("No FIT image loaded")
	}
	return false, fmt.Errorf("Unimplemented")
}

func Test26IBBCoversResetVector() (bool, error) {
	if len(fitImage) == 0 {
		return false, fmt.Errorf("No FIT image loaded")
	}
	return false, fmt.Errorf("Unimplemented")
}

func Test27NoIBBOverlap() (bool, error) {
	if len(fitImage) == 0 {
		return false, fmt.Errorf("No FIT image loaded")
	}
	return false, fmt.Errorf("Unimplemented")
}

func Test28NoBIOSACMOverlap() (bool, error) {
	if len(fitImage) == 0 {
		return false, fmt.Errorf("No FIT image loaded")
	}
	return false, fmt.Errorf("Unimplemented")
}

func Test29BIOSACMIsAbove4G() (bool, error) {
	if len(fitImage) == 0 {
		return false, fmt.Errorf("No FIT image loaded")
	}
	return false, fmt.Errorf("Unimplemented")
}

func Test30PolicyAllowsTXT() (bool, error) {
	if len(fitImage) == 0 {
		return false, fmt.Errorf("No FIT image loaded")
	}
	return false, fmt.Errorf("Unimplemented")
}

func Test31BIOSACMValid() (bool, error) {
	if len(fitImage) == 0 {
		return false, fmt.Errorf("No FIT image loaded")
	}
	return false, fmt.Errorf("Unimplemented")
}

func Test32BIOSACMSizeCorrect() (bool, error) {
	if len(fitImage) == 0 {
		return false, fmt.Errorf("No FIT image loaded")
	}
	return false, fmt.Errorf("Unimplemented")
}

func Test33BIOSACMAlignmentCorrect() (bool, error) {
	if len(fitImage) == 0 {
		return false, fmt.Errorf("No FIT image loaded")
	}
	return false, fmt.Errorf("Unimplemented")
}

func Test34BIOSACMMatchesChipset() (bool, error) {
	if len(fitImage) == 0 {
		return false, fmt.Errorf("No FIT image loaded")
	}
	return false, fmt.Errorf("Unimplemented")
}

func Test35BIOSACMMatchesCPU() (bool, error) {
	if len(fitImage) == 0 {
		return false, fmt.Errorf("No FIT image loaded")
	}
	return false, fmt.Errorf("Unimplemented")
}
