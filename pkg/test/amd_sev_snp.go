package test

import (
	"fmt"
	"strings"

	"github.com/9elements/go-linux-lowlevel-hw/pkg/hwapi"
	log "github.com/sirupsen/logrus"
	"golang.org/x/sys/unix"
)

var (
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
		Status:               NotImplemented,
		SpecificationChapter: "",
		SpecificiationTitle:  "AMD Secure Encrypted Virtualization-Secure Nested Paging",
		dependencies:         []*Test{&testAMDFamilyModel},
	}

	testSEVSNPSideChannelProtection = Test{
		Name:                 "Side-Channel Protection enabled",
		Required:             true,
		function:             SEVSNPSideChannelProtection,
		Status:               NotImplemented,
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
		Status:               NotImplemented,
		SpecificationChapter: "",
		SpecificiationTitle:  "AMD Secure Encrypted Virtualization-Secure Nested Paging",
		dependencies:         []*Test{&testAMDFamilyModel},
	}

	testSEVSNPAttestation = Test{
		Name:                 "SNP Attestation Reporting",
		Required:             true,
		function:             SEVSNPAttestation,
		Status:               NotImplemented,
		SpecificationChapter: "",
		SpecificiationTitle:  "AMD Secure Encrypted Virtualization-Secure Nested Paging",
		dependencies:         []*Test{&testAMDFamilyModel},
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

// SEV-SNP Tests

// SEVSNPSupport checks if SEV-SNP is supported by checking CPUID[0x8000001f].EAX[4]
func SEVSNPSupport(hw hwapi.LowLevelHardwareInterfaces, p *PreSet) (bool, error, error) {
	eax, _, _, _ := hw.CPUID(CPUID_SME_SEV, 0)
	if (eax & CPUID_SEV_SNP_SUPPORT) == CPUID_SEV_SNP_SUPPORT {
		log.Debugf("SEV-SNP is supported (CPUID.0x8000001f[EAX].bit[4] = 1)")
		return true, nil, nil
	}
	return false, fmt.Errorf("SEV-SNP is not supported on this CPU (CPUID.0x8000001f[EAX].bit[4] = 0)"), nil
}

// SEVSNPEnabled checks if SEV-SNP is enabled
func SEVSNPEnabled(hw hwapi.LowLevelHardwareInterfaces, p *PreSet) (bool, error, error) {
	vals := hw.ReadMSR(MSR_AMD64_SYSCFG)
	if len(vals) < 1 {
		return false, nil, fmt.Errorf("unable to red MSR: 0x%x", MSR_AMD64_SYSCFG)
	}
	if (vals[0] & MSR_AMD64_SYSCFG_SEVSNP_ENABLE) == MSR_AMD64_SYSCFG_SEVSNP_ENABLE {
		log.Debugf("SEV-SNP is enabled (MSR 0xC0010010[24] = 1")
		return true, nil, nil
	}
	return false, fmt.Errorf("feature SEV is not enabled (MSR 0xC0010131[0] != 1"), nil
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
	var buf strings.Builder
	splitString := "SEV-SNP API:"
	level := unix.SYSLOG_ACTION_READ_ALL
	b := make([]byte, 256*1024)
	amt, err := unix.Klogctl(level, b)
	if err != nil {
		return false, nil, fmt.Errorf("syslog failed: %w", err)
	}

	_, err = buf.Write(b[:amt])
	if err != nil {
		return false, nil, err
	}
	text := strings.SplitAfter(buf.String(), "\n")
	for _, line := range text {
		if !strings.Contains(line, splitString) {
			continue
		}
		l := strings.SplitAfter(line, "SEV")
		log.Infof("SEV-SNP Version found: %s", l[1])
		return true, nil, nil
	}
	return false, fmt.Errorf("no log with string 'SEV-SNP:' found"), nil
}
