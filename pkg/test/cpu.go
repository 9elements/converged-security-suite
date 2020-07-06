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
		function: CheckForIntelCPU,
		Status:   Implemented,
	}
	testwaybridgeorlater = Test{
		Name:         "Weybridge or later",
		function:     WeybridgeOrLater,
		Required:     true,
		dependencies: []*Test{&testcheckforintelcpu},
		Status:       Implemented,
	}
	testcpusupportstxt = Test{
		Name:         "CPU supports TXT",
		function:     CPUSupportsTXT,
		Required:     true,
		dependencies: []*Test{&testcheckforintelcpu},
		Status:       Implemented,
	}
	testtxtregisterspaceaccessible = Test{
		Name:     "TXT register space accessible",
		function: TXTRegisterSpaceAccessible,
		Required: true,
		Status:   Implemented,
	}
	testsupportssmx = Test{
		Name:         "CPU supports SMX",
		function:     SupportsSMX,
		Required:     true,
		dependencies: []*Test{&testcheckforintelcpu},
		Status:       Implemented,
	}
	testsupportvmx = Test{
		Name:         "CPU supports VMX",
		function:     SupportVMX,
		Required:     true,
		dependencies: []*Test{&testcheckforintelcpu},
		Status:       Implemented,
	}
	testia32featurectrl = Test{
		Name:         "IA32_FEATURE_CONTROL",
		function:     Ia32FeatureCtrl,
		Required:     true,
		dependencies: []*Test{&testcheckforintelcpu},
		Status:       Implemented,
	}
	testsmxisenabled = Test{
		Name:     "SMX enabled",
		function: SMXIsEnabled,
		Required: false,
		Status:   NotImplemented,
	}
	testtxtnotdisabled = Test{
		Name:     "TXT not disabled by BIOS",
		function: TXTNotDisabled,
		Required: true,
		Status:   Implemented,
	}
	testibbmeasured = Test{
		Name:         "BIOS ACM has run",
		function:     IBBMeasured,
		Required:     true,
		dependencies: []*Test{&testtxtregisterspaceaccessible},
		Status:       Implemented,
	}
	testibbistrusted = Test{
		Name:         "IBB is trusted",
		function:     IBBIsTrusted,
		Required:     false,
		NonCritical:  true,
		dependencies: []*Test{&testtxtregisterspaceaccessible},
		Status:       Implemented,
	}
	testtxtregisterslocked = Test{
		Name:         "TXT registers are locked",
		function:     TXTRegistersLocked,
		Required:     true,
		dependencies: []*Test{&testtxtregisterspaceaccessible},
		Status:       Implemented,
	}
	testia32debuginterfacelockeddisabled = Test{
		Name:         "IA32 debug interface isn't disabled",
		function:     IA32DebugInterfaceLockedDisabled,
		Required:     true,
		dependencies: []*Test{&testcheckforintelcpu},
		Status:       Implemented,
	}

	// TestsCPU exports slice with CPU related tests
	TestsCPU = [...]*Test{
		&testcheckforintelcpu,
		&testwaybridgeorlater,
		&testcpusupportstxt,
		&testtxtregisterspaceaccessible,
		&testsupportssmx,
		&testsupportvmx,
		&testia32featurectrl,
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

// CheckForIntelCPU Check we're running on a Intel CPU
func CheckForIntelCPU() (bool, error, error) {
	return api.VersionString() == "GenuineIntel", nil, nil
}

// WeybridgeOrLater Check we're running on Weybridge
func WeybridgeOrLater() (bool, error, error) {
	return cpuid.DisplayFamily == 6, nil, nil
}

// CPUSupportsTXT Check if the CPU supports TXT
func CPUSupportsTXT() (bool, error, error) {
	if api.CPUWhitelistTXTSupport() {
		return true, nil, nil
	}
	if api.CPUBlacklistTXTSupport() {
		return false, fmt.Errorf("CPU does not support TXT - on blacklist"), nil
	}
	return true, nil, nil
}

// TXTRegisterSpaceAccessible Check if the TXT register space is accessible
func TXTRegisterSpaceAccessible() (bool, error, error) {
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

// SupportsSMX Check if CPU supports SMX
func SupportsSMX() (bool, error, error) {
	return api.HasSMX(), nil, nil
}

// SupportVMX Check if CPU supports VMX
func SupportVMX() (bool, error, error) {
	return api.HasVMX(), nil, nil
}

// Ia32FeatureCtrl Check IA_32FEATURE_CONTROL
func Ia32FeatureCtrl() (bool, error, error) {
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

// SMXIsEnabled not implemented
func SMXIsEnabled() (bool, error, error) {
	return false, nil, fmt.Errorf("Unimplemented: no comment")
}

// Check CR4 wherther SMXE is set
//func TestSMXIsEnabled() (bool, error) {
//	return api.SMXIsEnabled(), nil
//}

// TXTNotDisabled Check TXT_DISABLED bit in TXT_ACM_STATUS
func TXTNotDisabled() (bool, error, error) {
	ret, err := api.TXTLeavesAreEnabled()
	if err != nil {
		return false, nil, err
	}
	if ret != true {
		return false, fmt.Errorf("TXT disabled"), nil
	}
	return true, nil, nil
}

// IBBMeasured Verify that the IBB has been measured
func IBBMeasured() (bool, error, error) {
	regs, err := getTxtRegisters()
	if err != nil {
		return false, nil, err
	}

	if regs.BootStatus&(1<<62) == 0 && regs.BootStatus&(1<<63) != 0 {
		return true, nil, nil
	}

	return false, fmt.Errorf("Bootstatus register incorrect"), nil
}

// IBBIsTrusted Check that the IBB was deemed trusted
// Only set in Signed Policy mode
func IBBIsTrusted() (bool, error, error) {
	regs, err := getTxtRegisters()

	if err != nil {
		return false, nil, err
	}

	if regs.BootStatus&(1<<59) != 0 && regs.BootStatus&(1<<63) != 0 {
		return true, nil, nil
	}
	return false, fmt.Errorf("IBB not trusted"), err
}

// TXTRegistersLocked Verify that the TXT register space is locked
func TXTRegistersLocked() (bool, error, error) {
	regs, err := getTxtRegisters()
	if err != nil {
		return false, nil, err
	}

	return regs.Sts.PrivateOpen, nil, nil
}

// NoBIOSACMErrors Check that the BIOS ACM has no startup error
func NoBIOSACMErrors() (bool, error, error) {
	regs, err := getTxtRegisters()
	if err != nil {
		return false, nil, err
	}

	return !regs.ErrorCode.ValidInvalid, nil, nil
}

// IA32DebugInterfaceLockedDisabled checks if IA32 debug interface is locked
func IA32DebugInterfaceLockedDisabled() (bool, error, error) {
	locked, pchStrap, enabled, err := api.IA32DebugInterfaceEnabledOrLocked()
	if err != nil {
		return false, nil, err
	}
	if !pchStrap {
		if locked && !enabled {
			return true, nil, nil
		}
		return false, fmt.Errorf("ia32 jtag isn't locked or disabled"), nil
	}
	return false, fmt.Errorf("ia32 jtag is force enabled by a hardware strap"), nil
}
