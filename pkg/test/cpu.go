package test

import (
	"github.com/9elements/txt-suite/pkg/api"
	"github.com/intel-go/cpuid"

	"fmt"
)

var (
	txtRegisterValues *api.TXTRegisterSpace = nil
)

func getTxtRegisters() (*api.TXTRegisterSpace, error) {
	if txtRegisterValues == nil {
		regs, err := api.ReadTXTRegs()
		if err != nil {
			return nil, err
		}

		txtRegisterValues = &regs
	}

	return txtRegisterValues, nil
}

// Check we're running on a Intel CPU
func Test01CheckForIntelCPU() (bool, error) {
	return api.VersionString() == "GenuineIntel", nil
}

// Check we're running on Weybridge
func Test02WeybridgeOrLater() (bool, error) {
	return cpuid.DisplayFamily == 6, nil
}

// Check if the CPU supports TXT
func Test03CPUSupportsTXT() (bool, error) {
	return api.ArchitectureTXTSupport()
}

// Check whether chipset supports TXT
func Test04ChipsetSupportsTXT() (bool, error) {
	return false, fmt.Errorf("Unimplemented")
}

// Check if the TXT register space is accessible
func Test05TXTRegisterSpaceAccessible() (bool, error) {
	regs, err := getTxtRegisters()
	if err != nil {
		return false, err
	}

	return regs.Vid == 0x8086, nil
}

// Check if CPU supports SMX
func Test06SupportsSMX() (bool, error) {
	return api.HasSMX(), nil
}

// Check if CPU supports VMX
func Test07SupportVMX() (bool, error) {
	return api.HasVMX(), nil
}

// Check IA_32FEATURE_CONTROL
func Test08Ia32FeatureCtrl() (bool, error) {
	vmxInSmx, err := api.AllowsVMXInSMX()
	if err != nil || !vmxInSmx {
		return vmxInSmx, err
	}

	locked, err := api.IA32FeatureControlIsLocked()
	if err != nil {
		return false, err
	}

	return locked, nil
}

// Check CR4 wherther SMXE is set
func Test09SMXIsEnabled() (bool, error) {
	return api.SMXIsEnabled(), nil
}

// Check that the BIOS ACM has no startup error
func Test10NoBIOSACMErrors() (bool, error) {
	regs, err := getTxtRegisters()
	if err != nil {
		return false, err
	}

	return !regs.ErrorCode.ValidInvalid, nil
}

func RunCPUTests() (bool, error) {
	fmt.Printf("Intel CPU: ")
	rc, err := Test01CheckForIntelCPU()
	if err != nil {
		fmt.Printf("ERROR\n\t%s\n", err)
		return false, nil
	}
	if rc {
		fmt.Println("OK")
	} else {
		fmt.Println("FAIL\n\tTXT only works on Intel CPUs")
		return false, nil
	}

	fmt.Printf("Weybridge or later: ")
	rc, err = Test02WeybridgeOrLater()
	if err != nil {
		fmt.Printf("ERROR\n\t%s\n", err)
		return false, nil
	}
	if rc {
		fmt.Println("OK")
	} else {
		fmt.Println("FAIL\n\tTXT only works on Intel CPUs")
		return false, nil
	}

	fmt.Printf("CPU supports TXT: ")
	rc, err = Test03CPUSupportsTXT()
	if err != nil {
		fmt.Printf("ERROR\n\t%s\n", err)
		return false, nil
	}
	if rc {
		fmt.Println("OK")
	} else {
		fmt.Println("FAIL\n\tTXT only works on Intel CPUs")
		return false, nil
	}

	//fmt.Printf("Chipset supports TXT: ")
	//rc, err = Test04ChipsetSupportsTXT()
	//if err != nil {
	//	fmt.Printf("ERROR\n\t%s\n", err)
	//	return false, nil
	//}
	//if rc {
	//	fmt.Println("OK")
	//} else {
	//	fmt.Println("FAIL\n\tTXT only works on Intel CPUs")
	//	return false, nil
	//}

	fmt.Printf("TXT register space accessible: ")
	rc, err = Test05TXTRegisterSpaceAccessible()
	if err != nil {
		fmt.Printf("ERROR\n\t%s\n", err)
		return false, nil
	}
	if rc {
		fmt.Println("OK")
	} else {
		fmt.Println("FAIL\n\tTXT only works on Intel CPUs")
		return false, nil
	}

	fmt.Printf("CPU supports SMX: ")
	rc, err = Test06SupportsSMX()
	if err != nil {
		fmt.Printf("ERROR\n\t%s\n", err)
		return false, nil
	}
	if rc {
		fmt.Println("OK")
	} else {
		fmt.Println("FAIL\n\tTXT only works on Intel CPUs")
		return false, nil
	}

	fmt.Printf("CUP supports VMX: ")
	rc, err = Test07SupportVMX()
	if err != nil {
		fmt.Printf("ERROR\n\t%s\n", err)
		return false, nil
	}
	if rc {
		fmt.Println("OK")
	} else {
		fmt.Println("FAIL\n\tTXT only works on Intel CPUs")
		return false, nil
	}

	fmt.Printf("IA32_FEATURE_CONTROL: ")
	rc, err = Test08Ia32FeatureCtrl()
	if err != nil {
		fmt.Printf("ERROR\n\t%s\n", err)
		return false, nil
	}
	if rc {
		fmt.Println("OK")
	} else {
		fmt.Println("FAIL\n\tTXT only works on Intel CPUs")
		return false, nil
	}

	//fmt.Printf("SMX enabled: ")
	//rc, err = Test09SMXIsEnabled()
	//if err != nil {
	//	fmt.Printf("ERROR\n\t%s\n", err)
	//	return false, nil
	//}
	//if rc {
	//	fmt.Println("OK")
	//} else {
	//	fmt.Println("FAIL\n\tTXT only works on Intel CPUs")
	//	return false, nil
	//}

	fmt.Printf("No ACM BIOS error: ")
	rc, err = Test10NoBIOSACMErrors()
	if err != nil {
		fmt.Printf("ERROR\n\t%s\n", err)
		return false, nil
	}
	if rc {
		fmt.Println("OK")
	} else {
		fmt.Println("FAIL\n\tTXT only works on Intel CPUs")
		return false, nil
	}

	return true, nil
}
