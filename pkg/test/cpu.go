package test

import (
	"github.com/9elements/converged-security-suite/v2/pkg/hwapi"
	"github.com/9elements/converged-security-suite/v2/pkg/tools"
	"github.com/intel-go/cpuid"

	"fmt"
)

var (
	txtRegisterValues    *tools.TXTRegisterSpace
	testcheckforintelcpu = Test{
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
		Name:                    "CPU supports SMX",
		function:                SupportsSMX,
		Required:                true,
		dependencies:            []*Test{&testcheckforintelcpu},
		Status:                  Implemented,
		SpecificationChapter:    "5.4.2 GETSEC Capability Control",
		SpecificiationTitle:     IntelTXTBGSBIOSSpecificationTitle,
		SpecificationDocumentID: IntelTXTBGSBIOSSpecificationDocumentID,
	}
	testsupportvmx = Test{
		Name:         "CPU supports VMX",
		function:     SupportVMX,
		Required:     true,
		dependencies: []*Test{&testcheckforintelcpu},
		Status:       Implemented,
	}
	testia32featurectrl = Test{
		Name:                    "IA32_FEATURE_CONTROL",
		function:                Ia32FeatureCtrl,
		Required:                true,
		dependencies:            []*Test{&testcheckforintelcpu},
		Status:                  Implemented,
		SpecificationChapter:    "5.4.1 Intel TXT Opt-In Control",
		SpecificiationTitle:     IntelTXTBGSBIOSSpecificationTitle,
		SpecificationDocumentID: IntelTXTBGSBIOSSpecificationDocumentID,
	}
	testsmxisenabled = Test{
		Name:                    "SMX enabled",
		function:                SMXIsEnabled,
		Required:                false,
		Status:                  NotImplemented,
		SpecificationChapter:    "5.4.2 GETSEC Capability Control",
		SpecificiationTitle:     IntelTXTBGSBIOSSpecificationTitle,
		SpecificationDocumentID: IntelTXTBGSBIOSSpecificationDocumentID,
	}

	testtxtnotdisabled = Test{
		Name:                    "TXT not disabled by BIOS",
		function:                TXTNotDisabled,
		Required:                true,
		Status:                  Implemented,
		SpecificationChapter:    "5.4.1 Intel TXT Opt-In Control",
		SpecificiationTitle:     IntelTXTBGSBIOSSpecificationTitle,
		SpecificationDocumentID: IntelTXTBGSBIOSSpecificationDocumentID,
	}
	testibbmeasured = Test{
		Name:                    "BIOS ACM has run",
		function:                IBBMeasured,
		Required:                true,
		dependencies:            []*Test{&testtxtregisterspaceaccessible},
		Status:                  Implemented,
		SpecificationChapter:    "B.1.6 TXT.SPAD – BOOTSTATUS",
		SpecificiationTitle:     IntelTXTSpecificationTitle,
		SpecificationDocumentID: IntelTXTSpecificationDocumentID,
	}
	testibbistrusted = Test{
		Name:                    "IBB is trusted",
		function:                IBBIsTrusted,
		Required:                false,
		dependencies:            []*Test{&testtxtregisterspaceaccessible},
		Status:                  Implemented,
		SpecificationChapter:    "B.1.6 TXT.SPAD – BOOTSTATUS",
		SpecificiationTitle:     IntelTXTSpecificationTitle,
		SpecificationDocumentID: IntelTXTSpecificationDocumentID,
	}
	testtxtregisterslocked = Test{
		Name:         "TXT registers are locked",
		function:     TXTRegistersLocked,
		Required:     true,
		dependencies: []*Test{&testtxtregisterspaceaccessible},
		Status:       Implemented,
	}
	testia32debuginterfacelockeddisabled = Test{
		Name:         "IA32 debug interface is disabled",
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

func getTxtRegisters(txtAPI hwapi.APIInterfaces) (*tools.TXTRegisterSpace, error) {

	if txtRegisterValues == nil {
		buf, err := tools.FetchTXTRegs(txtAPI)
		if err != nil {
			return nil, err
		}
		regs, err := tools.ParseTXTRegs(buf)
		if err != nil {
			return nil, err
		}

		txtRegisterValues = &regs
	}

	return txtRegisterValues, nil
}

// CheckForIntelCPU Check we're running on a Intel CPU
func CheckForIntelCPU(txtAPI hwapi.APIInterfaces, config *tools.Configuration) (bool, error, error) {
	if txtAPI.VersionString() == "GenuineIntel" {
		return true, nil, nil
	}
	return false, fmt.Errorf("No Intel CPU detected"), nil
}

// WeybridgeOrLater Check we're running on Weybridge
func WeybridgeOrLater(txtAPI hwapi.APIInterfaces, config *tools.Configuration) (bool, error, error) {
	if cpuid.DisplayFamily == 6 {
		return true, nil, nil
	}
	return false, fmt.Errorf("Platform is not Weybridge or later"), nil
}

// CPUSupportsTXT Check if the CPU supports TXT
func CPUSupportsTXT(txtAPI hwapi.APIInterfaces, config *tools.Configuration) (bool, error, error) {
	if txtAPI.CPUWhitelistTXTSupport() {
		return true, nil, nil
	}
	if txtAPI.CPUBlacklistTXTSupport() {
		return false, fmt.Errorf("CPU does not support TXT - on blacklist"), nil
	}
	return false, fmt.Errorf("CPU is not listed in any Intel CPU list"), nil
}

// TXTRegisterSpaceAccessible Check if the TXT register space is accessible
func TXTRegisterSpaceAccessible(txtAPI hwapi.APIInterfaces, config *tools.Configuration) (bool, error, error) {
	regs, err := getTxtRegisters(txtAPI)
	if err != nil {
		return false, nil, err
	}

	if regs.Vid != 0x8086 {
		return false, fmt.Errorf("TXTRegisterSpace: Unexpected VendorID"), nil
	}
	if regs.PublicKey[0] == 0xffffffffffffffff ||
		regs.PublicKey[1] == 0xffffffffffffffff ||
		regs.PublicKey[2] == 0xffffffffffffffff ||
		regs.PublicKey[3] == 0xffffffffffffffff {
		return false, fmt.Errorf("TXTRegisterSpace: Unexpected ACM public key"), nil
	}

	if regs.Did == 0x0 {
		return false, fmt.Errorf("TXTRegisterSpace: Unexpected: DeviceID is 0"), nil
	}
	return true, nil, nil
}

// SupportsSMX Check if CPU supports SMX
func SupportsSMX(txtAPI hwapi.APIInterfaces, config *tools.Configuration) (bool, error, error) {
	if txtAPI.HasSMX() {
		return true, nil, nil
	}
	return false, fmt.Errorf("CPU does not support SMX"), nil
}

// SupportVMX Check if CPU supports VMX
func SupportVMX(txtAPI hwapi.APIInterfaces, config *tools.Configuration) (bool, error, error) {
	if txtAPI.HasVMX() {
		return true, nil, nil
	}
	return false, fmt.Errorf("CPU does not support VMX"), nil
}

// Ia32FeatureCtrl Check IA_32FEATURE_CONTROL
func Ia32FeatureCtrl(txtAPI hwapi.APIInterfaces, config *tools.Configuration) (bool, error, error) {
	vmxInSmx, err := txtAPI.AllowsVMXInSMX()
	if err != nil || !vmxInSmx {
		return vmxInSmx, nil, err
	}

	locked, err := txtAPI.IA32FeatureControlIsLocked()
	if err != nil {
		return false, nil, err
	}

	if locked != true {
		return false, fmt.Errorf("IA32 Feature Control not locked"), nil
	}
	return true, nil, nil
}

// SMXIsEnabled not implemented
func SMXIsEnabled(txtAPI hwapi.APIInterfaces, config *tools.Configuration) (bool, error, error) {
	return false, nil, fmt.Errorf("Unimplemented: no comment")
}

// Check CR4 wherther SMXE is set
//func TestSMXIsEnabled() (bool, error) {
//	return api.SMXIsEnabled(), nil
//}

// TXTNotDisabled Check TXT_DISABLED bit in TXT_ACM_STATUS
func TXTNotDisabled(txtAPI hwapi.APIInterfaces, config *tools.Configuration) (bool, error, error) {
	ret, err := txtAPI.TXTLeavesAreEnabled()
	if err != nil {
		return false, nil, err
	}
	if ret != true {
		return false, fmt.Errorf("TXT disabled"), nil
	}
	return true, nil, nil
}

// IBBMeasured Verify that the IBB has been measured
func IBBMeasured(txtAPI hwapi.APIInterfaces, config *tools.Configuration) (bool, error, error) {
	regs, err := getTxtRegisters(txtAPI)
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
func IBBIsTrusted(txtAPI hwapi.APIInterfaces, config *tools.Configuration) (bool, error, error) {
	regs, err := getTxtRegisters(txtAPI)

	if err != nil {
		return false, nil, err
	}

	if regs.BootStatus&(1<<59) != 0 && regs.BootStatus&(1<<63) != 0 {
		return true, nil, nil
	}
	return false, fmt.Errorf("IBB not trusted"), err
}

// TXTRegistersLocked Verify that the TXT register space is locked
func TXTRegistersLocked(txtAPI hwapi.APIInterfaces, config *tools.Configuration) (bool, error, error) {
	regs, err := getTxtRegisters(txtAPI)
	if err != nil {
		return false, nil, err
	}
	if regs.Sts.PrivateOpen {
		return true, nil, nil
	}
	return false, fmt.Errorf("TXT register space is NOT locked"), nil
}

// NoBIOSACMErrors Check that the BIOS ACM has no startup error
func NoBIOSACMErrors(txtAPI hwapi.APIInterfaces, config *tools.Configuration) (bool, error, error) {
	regs, err := getTxtRegisters(txtAPI)
	if err != nil {
		return false, nil, err
	}
	if !regs.ErrorCode.ValidInvalid {
		return true, nil, nil
	}
	return false, fmt.Errorf("BIOS ACM had start up errors"), nil

}

// IA32DebugInterfaceLockedDisabled checks if IA32 debug interface is locked
func IA32DebugInterfaceLockedDisabled(txtAPI hwapi.APIInterfaces, config *tools.Configuration) (bool, error, error) {
	// Check for IA32_DEBUG_INTERFACE support
	if !cpuid.HasFeature(1 << 11) {
		// Nothing to check. Return success.
		return true, nil, nil
	}
	debug, err := txtAPI.IA32DebugInterfaceEnabledOrLocked()
	if err != nil {
		return false, nil, err
	}
	if !debug.PCHStrap {
		if debug.Locked && !debug.Enabled {
			return true, nil, nil
		}
		return false, fmt.Errorf("ia32 jtag isn't locked or disabled"), nil
	}
	return false, fmt.Errorf("ia32 jtag is force enabled by a hardware strap"), nil
}
