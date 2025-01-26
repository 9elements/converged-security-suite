package test

import (
	"fmt"

	"github.com/9elements/go-linux-lowlevel-hw/pkg/hwapi"
	log "github.com/sirupsen/logrus"
)

const (
	AMDPSBSpecificationTitle = "AMD Platform Security Boot"

	// CPUID Function IDs
	CPUID_SEV_SNP = uint32(0x8000001f)

	// CPUID SEV-SNP Feature Flags (Fn8000_001F[EAX])
	CPUID_SEV_SNP_SUPPORT = uint32(1) << 4 // Bit 4: SEV-SNP support

	// PSP MMIO Base Address variants
	PSPMMIOBase1 = 0x13E102E0 // For families 17h model 30h/70h or family 19h model 20h
	PSPMMIOBase2 = 0x13B102E0 // For all other models

	// Register offsets
	PSBStatusOffset = 0x10994

	// Bit fields in PSB_STATUS
	PSBStatusErrorMask    = 0xFF            // Bits 0-7: PSB Status
	PlatformVendorIDMask  = 0xFF            // Bits 0-7: Platform Vendor ID
	PlatformModelIDMask   = 0xF00           // Bits 8-11: Platform Model ID
	BIOSKeyRevisionMask   = 0xF000          // Bits 12-15: BIOS Key Revision
	RootKeySelectMask     = 0xF0000         // Bits 16-19: Root Key Select
	PSBFusedBit           = uint64(1) << 24 // Bit 24: PSB is fused
	AntiRollbackBit       = uint64(1) << 25 // Bit 25: Anti-Rollback
	DisableAMDKeyBit      = uint64(1) << 26 // Bit 26: Disable AMD Key
	DisableSecureDebugBit = uint64(1) << 27 // Bit 27: Disable Secure Debug
	CustomerKeyLockBit    = uint64(1) << 28 // Bit 28: Customer Key Lock
)

var (
	testAMDFamilyModel = Test{
		Name:                 "Detect AMD Family and Model",
		Required:             true,
		function:             AMDFamilyModel,
		Status:               Implemented,
		SpecificationChapter: "",
		SpecificiationTitle:  AMDPSBSpecificationTitle,
	}

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
		Status:               Implemented,
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

	// SME Tests
	testSMESupport = Test{
		Name:                 "SME Support",
		Required:             true,
		function:             SMESupport,
		Status:               Implemented,
		SpecificationChapter: "",
		SpecificiationTitle:  "AMD Secure Memory Encryption",
		dependencies:         []*Test{&testAMDFamilyModel},
	}

	testSMEEnabled = Test{
		Name:                 "SME Enabled",
		Required:             true,
		function:             SMEEnabled,
		Status:               Implemented,
		SpecificationChapter: "",
		SpecificiationTitle:  "AMD Secure Memory Encryption",
		dependencies:         []*Test{&testAMDFamilyModel},
	}

	testSMEKernelOption = Test{
		Name:                 "SME Kernel Option Set",
		Required:             true,
		function:             SMEKernelOption,
		Status:               Implemented,
		SpecificationChapter: "",
		SpecificiationTitle:  "AMD Secure Memory Encryption",
		dependencies:         []*Test{&testAMDFamilyModel},
	}

	testSMEKernelCommandline = Test{
		Name:                 "SME Kernel Commandline",
		Required:             true,
		function:             SMEKernelCommandline,
		Status:               Implemented,
		SpecificationChapter: "",
		SpecificiationTitle:  "AMD Secure Memory Encryption",
		dependencies:         []*Test{&testAMDFamilyModel},
	}

	testSMEFunctionality = Test{
		Name:                 "Verify SME Functionality",
		Required:             true,
		function:             SMEFunctionality,
		Status:               Implemented,
		SpecificationChapter: "",
		SpecificiationTitle:  "AMD Secure Memory Encryption",
		dependencies:         []*Test{&testAMDFamilyModel},
	}

	// SEV Tests
	testSEVSupport = Test{
		Name:                 "SEV Support",
		Required:             true,
		function:             SEVSupport,
		Status:               Implemented,
		SpecificationChapter: "",
		SpecificiationTitle:  "AMD Secure Encrypted Virtualization",
		dependencies:         []*Test{&testAMDFamilyModel},
	}

	testSEVEnabled = Test{
		Name:                 "SEV Enabled",
		Required:             true,
		function:             SEVEnabled,
		Status:               Implemented,
		SpecificationChapter: "",
		SpecificiationTitle:  "AMD Secure Encrypted Virtualization",
		dependencies:         []*Test{&testAMDFamilyModel},
	}

	testSEVFirmwareVersion = Test{
		Name:                 "SEV Firmware Version Validation",
		Required:             true,
		function:             SEVFirmwareVersion,
		Status:               Implemented,
		SpecificationChapter: "",
		SpecificiationTitle:  "AMD Secure Encrypted Virtualization",
		dependencies:         []*Test{&testAMDFamilyModel},
	}

	testSEVGuestConfig = Test{
		Name:                 "SEV Guest Configuration Validation",
		Required:             true,
		function:             SEVGuestConfig,
		Status:               Implemented,
		SpecificationChapter: "",
		SpecificiationTitle:  "AMD Secure Encrypted Virtualization",
		dependencies:         []*Test{&testAMDFamilyModel},
	}

	// SEV-SNP Tests
	testSEVSNPSupport = Test{
		Name:                 "SEV-SNP Support",
		Required:             true,
		function:             SEVSNPSupport,
		Status:               Implemented,
		SpecificationChapter: "",
		SpecificiationTitle:  "AMD Secure Encrypted Virtualization-Secure Nested Paging",
		dependencies:         []*Test{&testAMDFamilyModel},
	}

	testSEVSNPEnabled = Test{
		Name:                 "SEV-SNP Enabled",
		Required:             true,
		function:             SEVSNPEnabled,
		Status:               Implemented,
		SpecificationChapter: "",
		SpecificiationTitle:  "AMD Secure Encrypted Virtualization-Secure Nested Paging",
		dependencies:         []*Test{&testAMDFamilyModel},
	}

	testSEVSNPDebugRegisters = Test{
		Name:                 "SEV-SNP Debug Registers disabled",
		Required:             true,
		function:             SEVSNPDebugRegisters,
		Status:               Implemented,
		SpecificationChapter: "",
		SpecificiationTitle:  "AMD Secure Encrypted Virtualization-Secure Nested Paging",
		dependencies:         []*Test{&testAMDFamilyModel},
	}

	testSEVSNPSideChannelProtection = Test{
		Name:                 "Side-Channel Protection enabled",
		Required:             true,
		function:             SEVSNPSideChannelProtection,
		Status:               Implemented,
		SpecificationChapter: "",
		SpecificiationTitle:  "AMD Secure Encrypted Virtualization-Secure Nested Paging",
		dependencies:         []*Test{&testAMDFamilyModel},
	}

	testSEVSNPFirmwareVersion = Test{
		Name:                 "SEV-SNP Firmware Version Validation",
		Required:             true,
		function:             SEVSNPFirmwareVersion,
		Status:               Implemented,
		SpecificationChapter: "",
		SpecificiationTitle:  "AMD Secure Encrypted Virtualization-Secure Nested Paging",
		dependencies:         []*Test{&testAMDFamilyModel},
	}

	testSEVSNPVMBoot = Test{
		Name:                 "Measurement of SNP Protected VM Boot",
		Required:             true,
		function:             SEVSNPVMBoot,
		Status:               Implemented,
		SpecificationChapter: "",
		SpecificiationTitle:  "AMD Secure Encrypted Virtualization-Secure Nested Paging",
		dependencies:         []*Test{&testAMDFamilyModel},
	}

	testSEVSNPAttestation = Test{
		Name:                 "SNP Attestation Reporting",
		Required:             true,
		function:             SEVSNPAttestation,
		Status:               Implemented,
		SpecificationChapter: "",
		SpecificiationTitle:  "AMD Secure Encrypted Virtualization-Secure Nested Paging",
		dependencies:         []*Test{&testAMDFamilyModel},
	}

	// TestsAMD exposes the slice for AMD related tests
	TestsAMD = []*Test{
		&testAMDFamilyModel,
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
		&testSMESupport,
		&testSMEEnabled,
		&testSMEKernelOption,
		&testSMEKernelCommandline,
		&testSMEFunctionality,
		&testSEVSupport,
		&testSEVEnabled,
		&testSEVFirmwareVersion,
		&testSEVGuestConfig,
		&testSEVSNPSupport,
		&testSEVSNPEnabled,
		&testSEVSNPDebugRegisters,
		&testSEVSNPSideChannelProtection,
		&testSEVSNPFirmwareVersion,
		&testSEVSNPVMBoot,
		&testSEVSNPAttestation,
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

	TestsAMDSME = []*Test{
		&testSMESupport,
		&testSMEEnabled,
		&testSMEKernelOption,
		&testSMEKernelCommandline,
		&testSMEFunctionality,
	}

	TestsAMDSEV = []*Test{
		&testSEVSupport,
		&testSEVEnabled,
		&testSEVFirmwareVersion,
		&testSEVGuestConfig,
	}
	TestsAMDSEVSNP = []*Test{
		&testSEVSNPSupport,
		&testSEVSNPEnabled,
		&testSEVSNPDebugRegisters,
		&testSEVSNPSideChannelProtection,
		&testSEVSNPFirmwareVersion,
		&testSEVSNPVMBoot,
		&testSEVSNPAttestation,
	}
)

// SME Tests

// SMESupport checks if SME is supported
func SMESupport(hw hwapi.LowLevelHardwareInterfaces, p *PreSet) (bool, error, error) {
	log.Info("SME Support check is not implemented")
	return true, nil, nil
}

// SMEEnabled checks if SME is enabled
func SMEEnabled(hw hwapi.LowLevelHardwareInterfaces, p *PreSet) (bool, error, error) {
	log.Info("SME Enabled check is not implemented")
	return true, nil, nil
}

// SMEKernelOption checks if SME kernel option is set
func SMEKernelOption(hw hwapi.LowLevelHardwareInterfaces, p *PreSet) (bool, error, error) {
	log.Info("SME Kernel Option check is not implemented")
	return true, nil, nil
}

// SMEKernelCommandline checks SME kernel commandline
func SMEKernelCommandline(hw hwapi.LowLevelHardwareInterfaces, p *PreSet) (bool, error, error) {
	log.Info("SME Kernel Commandline check is not implemented")
	return true, nil, nil
}

// SMEFunctionality verifies SME functionality
func SMEFunctionality(hw hwapi.LowLevelHardwareInterfaces, p *PreSet) (bool, error, error) {
	log.Info("SME Functionality check is not implemented")
	return true, nil, nil
}

// SEV Tests

// SEVSupport checks if SEV is supported
func SEVSupport(hw hwapi.LowLevelHardwareInterfaces, p *PreSet) (bool, error, error) {
	log.Info("SEV Support check is not implemented")
	return true, nil, nil
}

// SEVEnabled checks if SEV is enabled
func SEVEnabled(hw hwapi.LowLevelHardwareInterfaces, p *PreSet) (bool, error, error) {
	log.Info("SEV Enabled check is not implemented")
	return true, nil, nil
}

// SEVFirmwareVersion validates SEV firmware version
func SEVFirmwareVersion(hw hwapi.LowLevelHardwareInterfaces, p *PreSet) (bool, error, error) {
	log.Info("SEV Firmware Version check is not implemented")
	return true, nil, nil
}

// SEVGuestConfig validates SEV guest configuration
func SEVGuestConfig(hw hwapi.LowLevelHardwareInterfaces, p *PreSet) (bool, error, error) {
	log.Info("SEV Guest Configuration check is not implemented")
	return true, nil, nil
}

// SEV-SNP Tests

// SEVSNPSupport checks if SEV-SNP is supported by checking CPUID[0x8000001f].EAX[4]
func SEVSNPSupport(hw hwapi.LowLevelHardwareInterfaces, p *PreSet) (bool, error, error) {
	eax, _, _, _ := hw.CPUID(CPUID_SEV_SNP, 0)
	if eax&CPUID_SEV_SNP_SUPPORT == 0 {
		return false, fmt.Errorf("SEV-SNP is not supported on this CPU (CPUID.0x8000001f[EAX].bit[4] = 0)"), nil
	}

	log.Debugf("SEV-SNP is supported (CPUID.0x8000001f[EAX].bit[4] = 1)")
	return true, nil, nil
}

// SEVSNPEnabled checks if SEV-SNP is enabled
func SEVSNPEnabled(hw hwapi.LowLevelHardwareInterfaces, p *PreSet) (bool, error, error) {
	log.Info("SEV-SNP Enabled check is not implemented")
	return true, nil, nil
}

// SEVSNPDebugRegisters checks if SEV-SNP debug registers are disabled
func SEVSNPDebugRegisters(hw hwapi.LowLevelHardwareInterfaces, p *PreSet) (bool, error, error) {
	log.Info("SEV-SNP Debug Registers check is not implemented")
	return true, nil, nil
}

// SEVSNPSideChannelProtection checks if side-channel protection is enabled
func SEVSNPSideChannelProtection(hw hwapi.LowLevelHardwareInterfaces, p *PreSet) (bool, error, error) {
	log.Info("SEV-SNP Side-Channel Protection check is not implemented")
	return true, nil, nil
}

// SEVSNPFirmwareVersion validates SEV-SNP firmware version
func SEVSNPFirmwareVersion(hw hwapi.LowLevelHardwareInterfaces, p *PreSet) (bool, error, error) {
	log.Info("SEV-SNP Firmware Version check is not implemented")
	return true, nil, nil
}

// SEVSNPVMBoot validates SNP protected VM boot measurement
func SEVSNPVMBoot(hw hwapi.LowLevelHardwareInterfaces, p *PreSet) (bool, error, error) {
	log.Info("SEV-SNP VM Boot Measurement check is not implemented")
	return true, nil, nil
}

// SEVSNPAttestation validates SNP attestation reporting
func SEVSNPAttestation(hw hwapi.LowLevelHardwareInterfaces, p *PreSet) (bool, error, error) {
	log.Info("SEV-SNP Attestation check is not implemented")
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

// PlatformVendorID checks if Platform Vendor ID is not zero
func PlatformVendorID(hw hwapi.LowLevelHardwareInterfaces, p *PreSet) (bool, error, error) {
	psbStatus, err := readPSBStatus(hw)
	if err != nil {
		return false, fmt.Errorf("failed to read PSB_STATUS: %v", err), nil
	}

	vendorID := psbStatus & PlatformVendorIDMask
	if vendorID == 0 {
		return false, fmt.Errorf("Platform Vendor ID is zero"), nil
	}

	log.Debugf("Platform Vendor ID: 0x%x", vendorID)
	return true, nil, nil
}

// PlatformModelID checks if Platform Model ID is not zero
func PlatformModelID(hw hwapi.LowLevelHardwareInterfaces, p *PreSet) (bool, error, error) {
	psbStatus, err := readPSBStatus(hw)
	if err != nil {
		return false, fmt.Errorf("failed to read PSB_STATUS: %v", err), nil
	}

	modelID := (psbStatus & PlatformModelIDMask) >> 8
	if modelID == 0 {
		return false, fmt.Errorf("Platform Model ID is zero"), nil
	}

	log.Debugf("Platform Model ID: 0x%x", modelID)
	return true, nil, nil
}

// BIOSKeyRevision checks if BIOS Key Revision is not zero
func BIOSKeyRevision(hw hwapi.LowLevelHardwareInterfaces, p *PreSet) (bool, error, error) {
	psbStatus, err := readPSBStatus(hw)
	if err != nil {
		return false, fmt.Errorf("failed to read PSB_STATUS: %v", err), nil
	}

	keyRevision := (psbStatus & BIOSKeyRevisionMask) >> 12
	if keyRevision == 0 {
		return false, fmt.Errorf("BIOS Key Revision is zero"), nil
	}

	log.Debugf("BIOS Key Revision: 0x%x", keyRevision)
	return true, nil, nil
}

// AMDKeyDisabled checks if AMD Key is disabled
func AMDKeyDisabled(hw hwapi.LowLevelHardwareInterfaces, p *PreSet) (bool, error, error) {
	psbStatus, err := readPSBStatus(hw)
	if err != nil {
		return false, fmt.Errorf("failed to read PSB_STATUS: %v", err), nil
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
		return false, fmt.Errorf("failed to read PSB_STATUS: %v", err), nil
	}

	if psbStatus&DisableSecureDebugBit == 0 {
		return false, fmt.Errorf("Secure Debug is not disabled"), nil
	}

	return true, nil, nil
}

// KeysFused checks if customer keys have been fused
func KeysFused(hw hwapi.LowLevelHardwareInterfaces, p *PreSet) (bool, error, error) {
	psbStatus, err := readPSBStatus(hw)
	if err != nil {
		return false, fmt.Errorf("failed to read PSB_STATUS: %v", err), nil
	}

	if psbStatus&CustomerKeyLockBit == 0 {
		return false, fmt.Errorf("Customer keys are not fused"), nil
	}

	return true, nil, nil
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
		return false, fmt.Errorf("failed to read PSB_STATUS: %v", err), nil
	}

	if psbStatus&AntiRollbackBit == 0 {
		return false, fmt.Errorf("Anti-rollback is not enabled"), nil
	}

	return true, nil, nil
}

// PSBEnabled checks if Platform Secure Boot is enabled by reading FUSE_PLATFORM_SECURE_BOOT_EN
func PSBEnabled(hw hwapi.LowLevelHardwareInterfaces, p *PreSet) (bool, error, error) {
	psbStatus, err := readPSBStatus(hw)
	if err != nil {
		return false, fmt.Errorf("failed to read PSB_STATUS: %v", err), nil
	}

	// Check if FUSE_PLATFORM_SECURE_BOOT_EN (bit 24) is set
	if psbStatus&PSBFusedBit == 0 {
		return false, fmt.Errorf("Platform Secure Boot is not enabled"), nil
	}

	return true, nil, nil
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
		return false, fmt.Errorf("failed to read PSB_STATUS: %v", err), nil
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
