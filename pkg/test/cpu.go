package test

import (
	"github.com/9elements/txt-suite/pkg/api"
	"github.com/intel-go/cpuid"

	"fmt"
)

var (
	txtRegisterValues      *api.TXTRegisterSpace = nil
	test01checkforintelcpu                       = Test{
		Name:     "Intel CPU",
		Required: true,
		function: Test01CheckForIntelCPU,
	}
	test02waybridgeorlater = Test{
		Name:         "Weybridge or later",
		function:     Test02WeybridgeOrLater,
		Required:     true,
		dependencies: []*Test{&test01checkforintelcpu},
	}
	test03cpusupportstxt = Test{
		Name:         "CPU supports TXT",
		function:     Test03CPUSupportsTXT,
		Required:     true,
		dependencies: []*Test{&test01checkforintelcpu},
	}
	test04chipsetsupportstxt = Test{
		Name:         "Chipset supports TXT",
		function:     Test04ChipsetSupportsTXT,
		Required:     false,
		dependencies: []*Test{&test01checkforintelcpu},
	}
	test05txtregisterspaceaccessible = Test{
		Name:         "TXT register space accessible",
		function:     Test05TXTRegisterSpaceAccessible,
		Required:     true,
		dependencies: []*Test{&test04chipsetsupportstxt},
	}
	test06supportssmx = Test{
		Name:         "CPU supports SMX",
		function:     Test06SupportsSMX,
		Required:     true,
		dependencies: []*Test{&test01checkforintelcpu},
	}
	test07supportvmx = Test{
		Name:         "CPU supports VMX",
		function:     Test07SupportVMX,
		Required:     true,
		dependencies: []*Test{&test01checkforintelcpu},
	}
	test08ia32featurectrl = Test{
		Name:         "IA32_FEATURE_CONTROL",
		function:     Test08Ia32FeatureCtrl,
		Required:     true,
		dependencies: []*Test{&test01checkforintelcpu},
	}
	test10hasgetsecleaves = Test{
		Name:         "GETSEC leaves are enabled",
		function:     Test10HasGetSecLeaves,
		Required:     false,
		dependencies: []*Test{&test08ia32featurectrl},
	}
	test11txtnotdisabled = Test{
		Name:     "Intel TXT no disabled by BIOS",
		function: Test11TXTNotDisabled,
		Required: true,
	}
	test12ibbmeasured = Test{
		Name:         "BIOS ACM has run",
		function:     Test12IBBMeasured,
		Required:     true,
		dependencies: []*Test{&test05txtregisterspaceaccessible},
	}
	test13ibbistrusted = Test{
		Name:         "Initial Bootblock is trusted. Only necessary in signed policy",
		function:     Test13IBBIsTrusted,
		Required:     false,
		dependencies: []*Test{&test05txtregisterspaceaccessible},
	}
	test14txtregisterslocked = Test{
		Name:         "Intel TXT registers are locked",
		function:     Test14TXTRegistersLocked,
		Required:     true,
		dependencies: []*Test{&test05txtregisterspaceaccessible},
	}
	TestsCPU = [...]*Test{
		&test01checkforintelcpu,
		&test02waybridgeorlater,
		&test03cpusupportstxt,
		&test04chipsetsupportstxt,
		&test05txtregisterspaceaccessible,
		&test06supportssmx,
		&test07supportvmx,
		&test08ia32featurectrl,
		&test10hasgetsecleaves,
		&test11txtnotdisabled,
		&test12ibbmeasured,
		&test13ibbistrusted,
		&test14txtregisterslocked,
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

func Test09SMXIsEnabled() (bool, error) {
	return false, fmt.Errorf("Unimplemented: no comment")
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

	return regs.AcmStatus&(1<<62) == 0 && regs.AcmStatus&(1<<63) != 0, nil
}

// Check that the IBB was deemed trusted
// Only set in Signed Policy mode
func Test13IBBIsTrusted() (bool, error) {
	regs, err := getTxtRegisters()

	if err != nil {
		return false, err
	}

	return regs.AcmStatus&(1<<59) != 0 && regs.AcmStatus&(1<<63) != 0, nil
}

// Verify that the TXT register space is locked
func Test14TXTRegistersLocked() (bool, error) {
	regs, err := getTxtRegisters()
	if err != nil {
		return false, err
	}

	return regs.Sts.PrivateOpen, nil
}

// Check that the BIOS ACM has no startup error
func Test15NoBIOSACMErrors() (bool, error) {
	regs, err := getTxtRegisters()
	if err != nil {
		return false, err
	}

	return !regs.ErrorCode.ValidInvalid, nil
}
