package test

import (
	"fmt"

	"github.com/9elements/go-linux-lowlevel-hw/pkg/hwapi"
	log "github.com/sirupsen/logrus"
)

var (
	// PSP MMIO Base Address variants
	PSPMMIOBase1 = int64(0x13E102E0) // For families 17h model 30h/70h or family 19h model 20h
	PSPMMIOBase2 = int64(0x13B102E0) // For all other models

	// Register offsets
	PSBStatusOffset = int64(0x10994)

	// Bit fields in PSB_STATUS
	PSBStatusErrorMask    = uint64(0xFF)    // Bits 0-7: PSB Status // Only from BMC
	PlatformVendorIDMask  = uint64(0xFF)    // Bits 0-7: Platform Vendor ID
	PlatformModelIDMask   = uint64(0xF00)   // Bits 8-11: Platform Model ID
	BIOSKeyRevisionMask   = uint64(0xF000)  // Bits 12-15: BIOS Key Revision
	RootKeySelectMask     = uint64(0xF0000) // Bits 16-19: Root Key Select
	PSBFusedBit           = uint64(1) << 24 // Bit 24: PSB is fused
	AntiRollbackBit       = uint64(1) << 25 // Bit 25: Anti-Rollback
	DisableAMDKeyBit      = uint64(1) << 26 // Bit 26: Disable AMD Key
	DisableSecureDebugBit = uint64(1) << 27 // Bit 27: Disable Secure Debug
	CustomerKeyLockBit    = uint64(1) << 28 // Bit 28: Customer Key Lock
)

var (
	testPSBStatus = Test{
		Name:                 "PSB Status Register contains zero value",
		Required:             true,
		function:             PSBStatus,
		Status:               Implemented,
		SpecificationChapter: "",
		SpecificiationTitle:  AMDPSBSpecificationTitle,
		dependencies:         []*Test{&testAMDFamilyModel},
	}

	testPSBEnabled = Test{
		Name:                 "Platform Secure Boot is enabled",
		Required:             true,
		function:             PSBEnabled,
		Status:               Implemented,
		SpecificationChapter: "",
		SpecificiationTitle:  AMDPSBSpecificationTitle,
		dependencies:         []*Test{&testAMDFamilyModel},
	}

	testPlatformVendorID = Test{
		Name:                 "Platform Vendor ID is not zero",
		Required:             true,
		function:             PlatformVendorID,
		Status:               Implemented,
		SpecificationChapter: "",
		SpecificiationTitle:  AMDPSBSpecificationTitle,
		dependencies:         []*Test{&testAMDFamilyModel},
	}

	testPlatformModelID = Test{
		Name:                 "Platform Model ID is not zero",
		Required:             true,
		function:             PlatformModelID,
		Status:               Implemented,
		SpecificationChapter: "",
		SpecificiationTitle:  AMDPSBSpecificationTitle,
		dependencies:         []*Test{&testAMDFamilyModel},
	}

	testBIOSKeyRevision = Test{
		Name:                 "BIOS Key Revision is not zero",
		Required:             true,
		function:             BIOSKeyRevision,
		Status:               Implemented,
		SpecificationChapter: "",
		SpecificiationTitle:  AMDPSBSpecificationTitle,
		dependencies:         []*Test{&testAMDFamilyModel},
	}

	testAMDKeyDisabled = Test{
		Name:                 "AMD Key is disabled",
		Required:             true,
		function:             AMDKeyDisabled,
		Status:               Implemented,
		SpecificationChapter: "",
		SpecificiationTitle:  AMDPSBSpecificationTitle,
		dependencies:         []*Test{&testAMDFamilyModel},
	}

	testSecureDebugDisabled = Test{
		Name:                 "Secure Debug is disabled",
		Required:             true,
		function:             SecureDebugDisabled,
		Status:               Implemented,
		SpecificationChapter: "",
		SpecificiationTitle:  AMDPSBSpecificationTitle,
		dependencies:         []*Test{&testAMDFamilyModel},
	}

	testKeysFused = Test{
		Name:                 "Keys are fused",
		Required:             true,
		function:             KeysFused,
		Status:               Implemented,
		SpecificationChapter: "",
		SpecificiationTitle:  AMDPSBSpecificationTitle,
		dependencies:         []*Test{&testAMDFamilyModel},
	}

	testPSBPolicyHash = Test{
		Name:                 "PSB Policy Hash",
		Required:             true,
		function:             PSBPolicyHash,
		Status:               NotImplemented,
		SpecificationChapter: "",
		SpecificiationTitle:  AMDPSBSpecificationTitle,
		dependencies:         []*Test{&testAMDFamilyModel},
	}

	testRevocationStatus = Test{
		Name:                 "Revocation Status",
		Required:             true,
		function:             RevocationStatus,
		Status:               Implemented,
		SpecificationChapter: "",
		SpecificiationTitle:  AMDPSBSpecificationTitle,
		dependencies:         []*Test{&testAMDFamilyModel},
	}

	TestsAMDPSP = []*Test{
		&testPSBStatus,
		&testPSBEnabled,
		&testPlatformVendorID,
		&testPlatformModelID,
		&testBIOSKeyRevision,
		&testAMDKeyDisabled,
		&testSecureDebugDisabled,
		&testKeysFused,
		&testPSBPolicyHash,
		&testRevocationStatus,
	}
)

// PlatformVendorID checks if Platform Vendor ID is not zero
func PlatformVendorID(hw hwapi.LowLevelHardwareInterfaces, p *PreSet) (bool, error, error) {
	psbStatus, err := readPSBStatus(hw)
	if err != nil {
		return false, nil, fmt.Errorf("failed to read PSB_STATUS: %v", err)
	}

	vendorID := psbStatus & PlatformVendorIDMask
	if vendorID == 0 {
		return false, fmt.Errorf("invalid Platform Vendor ID: 0x0"), nil
	}

	log.Infof("Platform Vendor ID: 0x%x", vendorID)
	return true, nil, nil
}

// PlatformModelID checks if Platform Model ID is not zero
func PlatformModelID(hw hwapi.LowLevelHardwareInterfaces, p *PreSet) (bool, error, error) {
	psbStatus, err := readPSBStatus(hw)
	if err != nil {
		return false, nil, fmt.Errorf("failed to read PSB_STATUS: %v", err)
	}

	modelID := (psbStatus & PlatformModelIDMask) >> 8
	if modelID == 0 {
		return false, fmt.Errorf("invalid Platform Model ID: 0x0"), nil
	}

	log.Infof("Platform Model ID: 0x%x", modelID)
	return true, nil, nil
}

// BIOSKeyRevision checks if BIOS Key Revision is not zero
func BIOSKeyRevision(hw hwapi.LowLevelHardwareInterfaces, p *PreSet) (bool, error, error) {
	psbStatus, err := readPSBStatus(hw)
	if err != nil {
		return false, nil, fmt.Errorf("failed to read PSB_STATUS: %v", err)
	}

	keyRevision := (psbStatus & BIOSKeyRevisionMask) >> 12
	if keyRevision == 0 {
		return false, fmt.Errorf("invalid BIOS Key Revision. Zero"), nil
	}

	log.Infof("BIOS Key Revision: 0x%x", keyRevision)
	return true, nil, nil
}

// AMDKeyDisabled checks if AMD Key is disabled
func AMDKeyDisabled(hw hwapi.LowLevelHardwareInterfaces, p *PreSet) (bool, error, error) {
	psbStatus, err := readPSBStatus(hw)
	if err != nil {
		return false, nil, fmt.Errorf("failed to read PSB_STATUS: %v", err)
	}

	if psbStatus&DisableAMDKeyBit == 0 {
		return false, fmt.Errorf("AMD Key is not disabled"), nil
	}

	return true, nil, nil
}

// SecureDebugDisabled checks if Secure Debug is disabled
func SecureDebugDisabled(hw hwapi.LowLevelHardwareInterfaces, p *PreSet) (bool, error, error) {
	psbStatus, err := readPSBStatus(hw)
	if err != nil {
		return false, nil, fmt.Errorf("failed to read PSB_STATUS: %v", err)
	}

	if (psbStatus & DisableSecureDebugBit) == DisableSecureDebugBit {
		return true, nil, nil
	}
	return false, fmt.Errorf("invalid Secure Debug value: 0x0"), nil
}

// KeysFused checks if customer keys have been fused
func KeysFused(hw hwapi.LowLevelHardwareInterfaces, p *PreSet) (bool, error, error) {
	psbStatus, err := readPSBStatus(hw)
	if err != nil {
		return false, nil, fmt.Errorf("failed to read PSB_STATUS: %v", err)
	}

	if (psbStatus & CustomerKeyLockBit) == CustomerKeyLockBit {
		return true, nil, nil
	}
	return false, fmt.Errorf("invalid value for Customer Key Lock bit: 0"), nil
}

// PSBPolicyHash checks and prints the PSB Policy Hash
func PSBPolicyHash(hw hwapi.LowLevelHardwareInterfaces, p *PreSet) (bool, error, error) {
	log.Info("PSB Policy Hash check is not implemented")
	return true, nil, nil
}

// RevocationStatus checks the revocation status
func RevocationStatus(hw hwapi.LowLevelHardwareInterfaces, p *PreSet) (bool, error, error) {
	psbStatus, err := readPSBStatus(hw)
	if err != nil {
		return false, nil, fmt.Errorf("failed to read PSB_STATUS: %v", err)
	}

	if psbStatus&AntiRollbackBit == 0 {
		return false, fmt.Errorf("feature Anti-rollback is not enabled"), nil
	}

	return true, nil, nil
}

// PSBEnabled checks if Platform Secure Boot is enabled by reading FUSE_PLATFORM_SECURE_BOOT_EN
func PSBEnabled(hw hwapi.LowLevelHardwareInterfaces, p *PreSet) (bool, error, error) {
	psbStatus, err := readPSBStatus(hw)
	if err != nil {
		return false, nil, fmt.Errorf("failed to read PSB_STATUS: %v", err)
	}

	// Check if FUSE_PLATFORM_SECURE_BOOT_EN (bit 24) is set
	if (psbStatus & PSBFusedBit) == PSBFusedBit {
		return true, nil, nil
	}
	return false, fmt.Errorf("feature Platform Secure Boot is not enabled"), nil
}

// getPSPMMIOBase determines the correct PSP MMIO Base Address based on CPU family/model
func getPSPMMIOBase(family, model uint32) int64 {
	if family == 0x17 && (model == 0x30 || model == 0x70) || (family == 0x19 && model == 0x20) {
		return PSPMMIOBase1
	}
	return PSPMMIOBase2
}

// PSBStatus checks if PSB_STATUS register contains zero value
// A non-zero value indicates an error
func PSBStatus(hw hwapi.LowLevelHardwareInterfaces, p *PreSet) (bool, error, error) {
	psbStatus, err := readPSBStatus(hw)
	if err != nil {
		return false, nil, fmt.Errorf("failed to read PSB_STATUS: %v", err)
	}

	// Check if PSB Status bits (0-7) are non-zero
	if psbStatus&PSBStatusErrorMask != 0 {
		return false, fmt.Errorf("PSB_STATUS contains non-zero value (0x%x)", psbStatus&PSBStatusErrorMask), nil
	}

	return true, nil, nil
}

// AMDFamilyModel detects which AMD family the test suite is executed on
func AMDFamilyModel(hw hwapi.LowLevelHardwareInterfaces, p *PreSet) (bool, error, error) {
	// Get CPU vendor
	if hw.VersionString() != "AuthenticAMD" {
		return false, fmt.Errorf("not an AMD CPU"), nil
	}

	// Get CPUID
	cpuID := hw.CPUSignature()

	family := ((cpuID >> 20) & 0xFF) + ((cpuID >> 8) & 0xF)
	model := ((cpuID >> 12) & 0xF0) + ((cpuID >> 4) & 0xF)

	// Log CPU info but don't fail - this is informative
	log.Infof("AMD CPU Family: 0x%x, Model: 0x%x", family, model)

	if family == 0x00 {
		return false, nil, fmt.Errorf("CPU family is not supported")
	}

	if model == 0x00 {
		return false, nil, fmt.Errorf("CPU model is not supported")
	}

	return true, nil, nil
}

// readPSBStatus reads the PSB Status register and returns its value
func readPSBStatus(hw hwapi.LowLevelHardwareInterfaces) (uint64, error) {
	cpuID := hw.CPUSignature()
	family := ((cpuID >> 20) & 0xFF) + ((cpuID >> 8) & 0xF)
	model := ((cpuID >> 12) & 0xF0) + ((cpuID >> 4) & 0xF)

	pspBase := getPSPMMIOBase(family, model)

	buf := make([]byte, 8)
	err := hw.ReadPhysBuf(pspBase+PSBStatusOffset, buf)
	if err != nil {
		return 0, fmt.Errorf("cannot read PSB_STATUS register: %w", err)
	}

	psbStatus := uint64(buf[0]) | uint64(buf[1])<<8 | uint64(buf[2])<<16 |
		uint64(buf[3])<<24 | uint64(buf[4])<<32 | uint64(buf[5])<<40 |
		uint64(buf[6])<<48 | uint64(buf[7])<<56

	log.Debugf("PSB_STATUS: 0x%x", psbStatus)
	return psbStatus, nil
}
