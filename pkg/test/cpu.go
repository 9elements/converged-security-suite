package test

import (
	"github.com/9elements/txt-suite/pkg/api"
	"github.com/intel-go/cpuid"

	"fmt"
)

var (
	txtRegisterValues *api.TXTRegisterSpace = nil
	TestsCPU                                = [...]Test{
		Test{
			Name:     "Intel CPU",
			Required: true,
			function: Test01CheckForIntelCPU,
		},
		Test{
			Name:     "Weybridge or later",
			function: Test02WeybridgeOrLater,
			Required: true,
		},
		Test{
			Name:     "CPU supports TXT",
			function: Test03CPUSupportsTXT,
			Required: true,
		},
		Test{
			Name:     "Chipset supports TXT",
			function: Test04ChipsetSupportsTXT,
			Required: false,
		},
		Test{
			Name:     "TXT register space accessible",
			function: Test05TXTRegisterSpaceAccessible,
			Required: true,
		},
		Test{
			Name:     "CPU supports SMX",
			function: Test06SupportsSMX,
			Required: true,
		},
		Test{
			Name:     "CPU supports VMX",
			function: Test07SupportVMX,
			Required: true,
		},
		Test{
			Name:     "IA32_FEATURE_CONTROL",
			function: Test08Ia32FeatureCtrl,
			Required: true,
		},
		Test{
			Name:     "GETSEC leaves are enabled",
			function: Test10HasGetSecLeaves,
			Required: false,
		},
		Test{
			Name:     "Intel TXT no disabled by BIOS",
			function: Test11TXTNotDisabled,
			Required: true,
		},
		Test{
			Name:     "BIOS ACM has run",
			function: Test12IBBMeasured,
			Required: true,
		},
		Test{
			Name:     "Initial Bootblock is trusted",
			function: Test13IBBIsTrusted,
			Required: true,
		},
		Test{
			Name:     "Intel TXT registers are locked",
			function: Test14TXTRegistersLocked,
			Required: true,
		},
	}
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
	return false, fmt.Errorf("Unimplemented: Linux disables GETSEC by clearing CR4.SMXE")
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
//func Test09SMXIsEnabled() (bool, error) {
//	return api.SMXIsEnabled(), nil
//}

// Check for needed GETSEC leaves
func Test10HasGetSecLeaves() (bool, error) {
	return false, fmt.Errorf("Unimplemented: Linux disables GETSEC by clearing CR4.SMXE")
}

// Check TXT_DISABLED bit in TXT_ACM_STATUS
func Test11TXTNotDisabled() (bool, error) {
	return api.TXTLeavesAreEnabled()
}

// Verify that the IBB has been measured
func Test12IBBMeasured() (bool, error) {
	regs, err := getTxtRegisters()
	if err != nil {
		return false, err
	}

	return regs.AcmStatus&(1<<62) != 0, nil
}

// Check that the IBB was deemed trusted
func Test13IBBIsTrusted() (bool, error) {
	regs, err := getTxtRegisters()

	if err != nil {
		return false, err
	}

	return regs.AcmStatus&(1<<59) != 0, nil
}

// Verify that the TXT register space is locked
func Test14TXTRegistersLocked() (bool, error) {
	return false, fmt.Errorf("Unimplemented")
}

// Check that the BIOS ACM has no startup error
func Test15NoBIOSACMErrors() (bool, error) {
	regs, err := getTxtRegisters()
	if err != nil {
		return false, err
	}

	return !regs.ErrorCode.ValidInvalid, nil
}
