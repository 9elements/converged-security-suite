package test

import (
	"github.com/9elements/txt-suite/pkg/api"
	"github.com/intel-go/cpuid"

	"fmt"
)

var (
	txtRegisterValues    *api.TXTRegisterSpace = nil
	testcheckforintelcpu                       = Test{
		Name:     "Intel CPU",
		Required: true,
		function: TestCheckForIntelCPU,
		Status:   TestImplemented,
	}
	testwaybridgeorlater = Test{
		Name:         "Weybridge or later",
		function:     TestWeybridgeOrLater,
		Required:     true,
		dependencies: []*Test{&testcheckforintelcpu},
		Status:       TestImplemented,
	}
	testcpusupportstxt = Test{
		Name:         "CPU supports TXT",
		function:     TestCPUSupportsTXT,
		Required:     true,
		dependencies: []*Test{&testcheckforintelcpu},
		Status:       TestImplemented,
	}
	testchipsetsupportstxt = Test{
		Name:         "Chipset supports TXT",
		function:     TestChipsetSupportsTXT,
		Required:     false,
		dependencies: []*Test{&testcheckforintelcpu},
		Status:       TestNotImplemented,
	}
	testtxtregisterspaceaccessible = Test{
		Name:         "TXT register space accessible",
		function:     TestTXTRegisterSpaceAccessible,
		Required:     true,
		dependencies: []*Test{&testchipsetsupportstxt},
		Status:       TestImplemented,
	}
	testsupportssmx = Test{
		Name:         "CPU supports SMX",
		function:     TestSupportsSMX,
		Required:     true,
		dependencies: []*Test{&testcheckforintelcpu},
		Status:       TestImplemented,
	}
	testsupportvmx = Test{
		Name:         "CPU supports VMX",
		function:     TestSupportVMX,
		Required:     true,
		dependencies: []*Test{&testcheckforintelcpu},
		Status:       TestImplemented,
	}
	testia32featurectrl = Test{
		Name:         "IA32_FEATURE_CONTROL",
		function:     TestIa32FeatureCtrl,
		Required:     true,
		dependencies: []*Test{&testcheckforintelcpu},
		Status:       TestImplemented,
	}
	testhasgetsecleaves = Test{
		Name:         "GETSEC leaves are enabled",
		function:     TestHasGetSecLeaves,
		Required:     false,
		dependencies: []*Test{&testia32featurectrl},
		Status:       TestNotImplemented,
	}
	testsmxisenabled = Test{
		Name:     "SMX enabled",
		function: TestSMXIsEnabled,
		Required: false,
		Status:   TestNotImplemented,
	}
	testtxtnotdisabled = Test{
		Name:     "TXT not disabled by BIOS",
		function: TestTXTNotDisabled,
		Required: true,
		Status:   TestImplemented,
	}
	testibbmeasured = Test{
		Name:         "BIOS ACM has run",
		function:     TestIBBMeasured,
		Required:     true,
		dependencies: []*Test{&testtxtregisterspaceaccessible},
		Status:       TestImplemented,
	}
	testibbistrusted = Test{
<<<<<<< HEAD
		Name:         "Initial Bootblock is trusted",
=======
		Name:         "IBB is trusted",
>>>>>>> 777f801... Changed name of TestIBBIsTrusted to "IBB is trusted"
		function:     TestIBBIsTrusted,
		Required:     false,
		dependencies: []*Test{&testtxtregisterspaceaccessible},
		Status:       TestImplemented,
	}
	testtxtregisterslocked = Test{
		Name:         "TXT registers are locked",
		function:     TestTXTRegistersLocked,
		Required:     true,
		dependencies: []*Test{&testtxtregisterspaceaccessible},
		Status:       TestImplemented,
	}
	TestsCPU = [...]*Test{
		&testcheckforintelcpu,
		&testwaybridgeorlater,
		&testcpusupportstxt,
		&testchipsetsupportstxt,
		&testtxtregisterspaceaccessible,
		&testsupportssmx,
		&testsupportvmx,
		&testia32featurectrl,
		&testhasgetsecleaves,
		&testtxtnotdisabled,
		&testibbmeasured,
		&testibbistrusted,
		&testtxtregisterslocked,
	}
)

func getTxtRegisters() (*api.TXTRegisterSpace, error) {
	if txtRegisterValues == nil {
		buf, err := api.FetchTXTRegs()
		if err != nil {
			return nil, err
		}
		regs, err := api.ParseTXTRegs(buf)
		if err != nil {
			return nil, err
		}

		txtRegisterValues = &regs
	}

	return txtRegisterValues, nil
}

// Check we're running on a Intel CPU
func TestCheckForIntelCPU() (bool, error) {
	return api.VersionString() == "GenuineIntel", nil
}

// Check we're running on Weybridge
func TestWeybridgeOrLater() (bool, error) {
	return cpuid.DisplayFamily == 6, nil
}

// Check if the CPU supports TXT
func TestCPUSupportsTXT() (bool, error) {
	if CPUWhitelistTXTSupport() {
		return true, nil
	}
	if CPUBlacklistTXTSupport() {
		return false, nil
	}
	// Lookup name on Intel
	return api.ArchitectureTXTSupport()
}

// Check whether chipset supports TXT
func TestChipsetSupportsTXT() (bool, error) {
	return false, fmt.Errorf("Unimplemented: Linux disables GETSEC by clearing CR4.SMXE")
}

// Check if the TXT register space is accessible
func TestTXTRegisterSpaceAccessible() (bool, error) {
	regs, err := getTxtRegisters()
	if err != nil {
		return false, err
	}

	return regs.Vid == 0x8086, nil
}

// Check if CPU supports SMX
func TestSupportsSMX() (bool, error) {
	return api.HasSMX(), nil
}

// Check if CPU supports VMX
func TestSupportVMX() (bool, error) {
	return api.HasVMX(), nil
}

// Check IA_32FEATURE_CONTROL
func TestIa32FeatureCtrl() (bool, error) {
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

func TestSMXIsEnabled() (bool, error) {
	return false, fmt.Errorf("Unimplemented: no comment")
}

// Check CR4 wherther SMXE is set
//func TestSMXIsEnabled() (bool, error) {
//	return api.SMXIsEnabled(), nil
//}

// Check for needed GETSEC leaves
func TestHasGetSecLeaves() (bool, error) {
	return false, fmt.Errorf("Unimplemented: Linux disables GETSEC by clearing CR4.SMXE")
}

// Check TXT_DISABLED bit in TXT_ACM_STATUS
func TestTXTNotDisabled() (bool, error) {
	return api.TXTLeavesAreEnabled()
}

// Verify that the IBB has been measured
func TestIBBMeasured() (bool, error) {
	regs, err := getTxtRegisters()
	if err != nil {
		return false, err
	}

	return regs.BootStatus&(1<<62) == 0 && regs.BootStatus&(1<<63) != 0, nil
}

// Check that the IBB was deemed trusted
// Only set in Signed Policy mode
func TestIBBIsTrusted() (bool, error) {
	regs, err := getTxtRegisters()

	if err != nil {
		return false, err
	}

	return regs.BootStatus&(1<<59) != 0 && regs.BootStatus&(1<<63) != 0, nil
}

// Verify that the TXT register space is locked
func TestTXTRegistersLocked() (bool, error) {
	regs, err := getTxtRegisters()
	if err != nil {
		return false, err
	}

	return regs.Sts.PrivateOpen, nil
}

// Check that the BIOS ACM has no startup error
func TestNoBIOSACMErrors() (bool, error) {
	regs, err := getTxtRegisters()
	if err != nil {
		return false, err
	}

	return !regs.ErrorCode.ValidInvalid, nil
}
