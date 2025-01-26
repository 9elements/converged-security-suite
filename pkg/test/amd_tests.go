package test

import (
	"github.com/9elements/go-linux-lowlevel-hw/pkg/hwapi"
	log "github.com/sirupsen/logrus"
)

const (
	AMDPSBSpecificationTitle = "AMD Platform Security Boot"

	// CPUID Function IDs
	CPUID_SME_SEV = uint32(0x8000001f)

	// CPUID SEV-SNP Feature Flags (Fn8000_001F[EAX])
	CPUID_SME_SUPPORT                 = uint32(1) << 0  // Bit 0: SME support
	CPUID_SEV_SUPPORT                 = uint32(1) << 1  // Bit 1: SEV support
	CPUID_SEV_ES_SUPPORT              = uint32(1) << 3  // Bit 3: SEV-ES support
	CPUID_SEV_SNP_SUPPORT             = uint32(1) << 4  // Bit 4: SEV-SNP support
	CPUID_VM_PERMISSION_LEVEL_SUPPORT = uint32(1) << 5  // Bit 5: VM Permission Level support
	CPUID_RMPQUERY_SUPPORT            = uint32(1) << 6  // Bit 6: RMPQUERY Instruction supported
	CPUID_VMPLSHADOW_STACK_SUPPORT    = uint32(1) << 7  // Bit 7: VM Permissino Level Shadow Stack support
	CPUID_SECURE_TSC_Support          = uint32(1) << 8  // Bit 8: SecureTsc support
	CPUID_TSC_AUX_VIRT_SUPPORT        = uint32(1) << 9  // Bit 9: TSC AuxVirtualization support
	CPUID_HW_CACHE_COHERENCY_ENFORCED = uint32(1) << 10 // Bit 10: Hardware cache coherency across encryption domains enforced
	CPUID_TSME_SUPPORT                = uint32(1) << 13 // Bit 13: TSME support

	// MSRs
	MSR_AMD64_SYSCFG = 0xC0010010

	// MSR bits
	// MSR SYSCFG bits
	MSR_AMD64_SYSCFG_SME_ENABLE          = uint64(1) << 23 // Bit 23: SME Enable
	MSR_AMD64_SYSCFG_SEVSNP_ENABLE       = uint64(1) << 24 // Bit 24: SEV-SNP Enable
	MSR_AMD64_SYSCFG_SME_MULTIKEY_ENABLE = uint64(1) << 26 // Bit 24: SEV-SNP Enable

	// MSR_AMD64_SEV not viable for host/hypervisor envirnoment, only guest.
	MSR_AMD64_SEV = 0xC0010131
	// MSR SEV bits in VM
	MSR_AMD64_SEV_ENABLED    = uint64(1) << 0 // Bit 0: SEV Enable
	MSR_AMD64_SEV_ES_ENABLED = uint64(1) << 1 // Bit 1: SEV-ES Enable

	MSR_AMD64_SYSCFG_TSME_EN = uint64(1) << 18 // Bit 18: TSME Enable (MSR 0xC0010010[18])
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

	testTSMESupport = Test{
		Name:                 "TSME Support",
		Required:             true,
		function:             TSMESupport,
		Status:               Implemented,
		SpecificationChapter: "",
		SpecificiationTitle:  "AMD Transparent Secure Memory Encryption",
		dependencies:         []*Test{&testAMDFamilyModel},
	}

	testTSMEEnabled = Test{
		Name:                 "TSME Enabled",
		Required:             true,
		function:             TSMEEnabled,
		Status:               Implemented,
		SpecificationChapter: "",
		SpecificiationTitle:  "AMD Transparent Secure Memory Encryption",
		dependencies:         []*Test{&testAMDFamilyModel},
	}

	// SEV Tests
	testSEVSupport = Test{
		Name:                 "SEV Enabled in BIOS",
		Required:             true,
		function:             SEVSupport,
		Status:               Implemented,
		SpecificationChapter: "E.4.17 Function 8000_001Fh—SEV Capabilities",
		SpecificiationTitle:  "AMD64 Architecture Programmer's Manual Volume 3: General Purpose and System Programming Instructions (PUB) (24594)",
		dependencies:         []*Test{&testAMDFamilyModel},
	}

	testSEVEnabledInSysFS = Test{
		Name:                 "SEV Enabled in SysFS",
		Required:             true,
		function:             SEVEnabledInSysFS,
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
		&testSMEKernelOption,
		&testSMEEnabled,

		&testSEVSupport,
		&testSEVEnabledInSysFS,
		&testSEVFirmwareVersion,

		&testSEVSNPSupport,
		&testSEVSNPEnabled,
		&testSEVSNPDebugRegisters,
		&testSEVSNPSideChannelProtection,
		&testSEVSNPFirmwareVersion,
		&testSEVSNPVMBoot,
		&testSEVSNPAttestation,
	}

	TestsAMDGeneral = []*Test{
		&testAMDFamilyModel,
	}
)

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
