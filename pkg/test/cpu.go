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
		Name:         "IBB is trusted",
		function:     TestIBBIsTrusted,
		Required:     false,
		NonCritical:  true,
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
	testia32debuginterfacelockeddisabled = Test{
		Name:         "IA32 debug interface isn't disabled",
		function:     TestIA32DebugInterfaceLockedDisabled,
		Required:     true,
		dependencies: []*Test{&testcheckforintelcpu},
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
		&testia32debuginterfacelockeddisabled,
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
func TestCheckForIntelCPU() (bool, error, error) {
	return api.VersionString() == "GenuineIntel", nil, nil
}

// Check we're running on Weybridge
func TestWeybridgeOrLater() (bool, error, error) {
	return cpuid.DisplayFamily == 6, nil, nil
}

// Check if the CPU supports TXT
func TestCPUSupportsTXT() (bool, error, error) {
	if api.CPUWhitelistTXTSupport() {
		return true, nil, nil
	}
	if api.CPUBlacklistTXTSupport() {
		return false, fmt.Errorf("CPU does not support TXT - on blacklist"), nil
	}
	return true, nil, nil
}

// Check whether chipset supports TXT
func TestChipsetSupportsTXT() (bool, error, error) {
	return false, nil, fmt.Errorf("Unimplemented: Linux disables GETSEC by clearing CR4.SMXE")
}

// Check if the TXT register space is accessible
func TestTXTRegisterSpaceAccessible() (bool, error, error) {
	regs, err := getTxtRegisters()
	if err != nil {
		return false, nil, err
	}

	if regs.Vid != 0x8086 {
		return false, fmt.Errorf("TXTRegisterSpace: Unexpected VendorID"), nil
	}

	if regs.HeapBase == 0x0 {
		return false, fmt.Errorf("TXTRegisterSpace: Unexpected: HeapBase is 0"), nil
	}

	if regs.SinitBase == 0x0 {
		return false, fmt.Errorf("TXTRegisterSpace: Unexpected: SinitBase is 0"), nil
	}

	if regs.Did == 0x0 {
		return false, fmt.Errorf("TXTRegisterSpace: Unexpected: DeviceID is 0"), nil
	}
	return true, nil, nil
}

// Check if CPU supports SMX
func TestSupportsSMX() (bool, error, error) {
	return api.HasSMX(), nil, nil
}

// Check if CPU supports VMX
func TestSupportVMX() (bool, error, error) {
	return api.HasVMX(), nil, nil
}

// Check IA_32FEATURE_CONTROL
func TestIa32FeatureCtrl() (bool, error, error) {
	vmxInSmx, err := api.AllowsVMXInSMX()
	if err != nil || !vmxInSmx {
		return vmxInSmx, nil, err
	}

	locked, err := api.IA32FeatureControlIsLocked()
	if err != nil {
		return false, nil, err
	}

	if locked != true {
		return false, fmt.Errorf("IA32 Feature Control not locked"), nil
	}
	return true, nil, nil
}

func TestSMXIsEnabled() (bool, error, error) {
	return false, nil, fmt.Errorf("Unimplemented: no comment")
}

// Check CR4 wherther SMXE is set
//func TestSMXIsEnabled() (bool, error) {
//	return api.SMXIsEnabled(), nil
//}

// Check for needed GETSEC leaves
func TestHasGetSecLeaves() (bool, error, error) {
	return false, nil, fmt.Errorf("Unimplemented: Linux disables GETSEC by clearing CR4.SMXE")
}

// Check TXT_DISABLED bit in TXT_ACM_STATUS
func TestTXTNotDisabled() (bool, error, error) {
	ret, err := api.TXTLeavesAreEnabled()
	if err != nil {
		return false, nil, err
	}
	if ret != true {
		return false, fmt.Errorf("TXT disabled"), nil
	}
	return true, nil, nil
}

// Verify that the IBB has been measured
func TestIBBMeasured() (bool, error, error) {
	regs, err := getTxtRegisters()
	if err != nil {
		return false, nil, err
	}

	if regs.BootStatus&(1<<62) == 0 && regs.BootStatus&(1<<63) != 0 {
		return true, nil, nil
	}

	return false, fmt.Errorf("Bootstatus register incorrect"), nil
}

// Check that the IBB was deemed trusted
// Only set in Signed Policy mode
func TestIBBIsTrusted() (bool, error, error) {
	regs, err := getTxtRegisters()

	if err != nil {
		return false, nil, err
	}

	if regs.BootStatus&(1<<59) != 0 && regs.BootStatus&(1<<63) != 0 {
		return true, nil, nil
	}
	return false, fmt.Errorf("IBB not trusted"), err
}

// Verify that the TXT register space is locked
func TestTXTRegistersLocked() (bool, error, error) {
	regs, err := getTxtRegisters()
	if err != nil {
		return false, nil, err
	}

	return regs.Sts.PrivateOpen, nil, nil
}

// Check that the BIOS ACM has no startup error
func TestNoBIOSACMErrors() (bool, error, error) {
	regs, err := getTxtRegisters()
	if err != nil {
		return false, nil, err
	}

	return !regs.ErrorCode.ValidInvalid, nil, nil
}

// TestIA32DebugInterfaceLockedDisabled checks if IA32 debug interface is locked
func TestIA32DebugInterfaceLockedDisabled() (bool, error, error) {
	locked, pchStrap, enabled, err := api.IA32DebugInterfaceEnabledOrLocked()
	if err != nil {
		return false, nil, err
	}
	if !pchStrap {
		if locked || !enabled {
			return true, nil, nil
		} else {
			return false, fmt.Errorf("ia32 jtag isn't locked or disabled"), nil
		}
	}
	return false, fmt.Errorf("ia32 jtag is force enabled by a hardware strap"), nil
}
