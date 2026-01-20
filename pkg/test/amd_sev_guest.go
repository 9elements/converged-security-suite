package test

import (
	"fmt"

	"github.com/9elements/go-linux-lowlevel-hw/pkg/hwapi"
	log "github.com/sirupsen/logrus"
)

var (
	testSEVGuestSEVEnabled = Test{
		Name:                 "SEV Enabled in MSR",
		Required:             false,
		function:             SEVGuestSEVEnabledInMSR,
		Status:               Implemented,
		SpecificationChapter: "15.34.10 SEV_STATUS MSR",
		SpecificiationTitle:  "AMD64 Architecture Programmer's Manual Volume 2: System Programming (PUB) (24593)",
		dependencies:         []*Test{&testAMDFamilyModel},
	}

	testSEVGuestSEVESEnabledCPU = Test{
		Name:                 "SEV-ES Enabled in BIOS",
		Required:             true,
		function:             SEVGuestSEVESEnabled,
		Status:               Implemented,
		SpecificationChapter: "",
		SpecificiationTitle:  "AMD Secure Encrypted Virtualization - Encrypted State",
		dependencies:         []*Test{&testAMDFamilyModel},
	}

	testSEVGuestConfig = Test{
		Name:                 "SEV Guest Configuration Validation",
		Required:             true,
		function:             SEVGuestConfig,
		Status:               NotImplemented,
		SpecificationChapter: "",
		SpecificiationTitle:  "AMD Secure Encrypted Virtualization",
		dependencies:         []*Test{&testAMDFamilyModel},
	}

	TestAMDSEVGuest = []*Test{
		&testSEVGuestSEVEnabled,
		&testSEVGuestSEVESEnabledCPU,
		&testSEVGuestConfig,
	}
)

// SEVEnabledInMSR checks if SEV is enabled by reading MSR 0xC0010131[0] (From guest)
func SEVGuestSEVEnabledInMSR(hw hwapi.LowLevelHardwareInterfaces, p *PreSet) (bool, error, error) {
	vals := hw.ReadMSR(MSR_AMD64_SEV)
	if len(vals) < 1 {
		return false, nil, fmt.Errorf("unable to red MSR: 0x%x", MSR_AMD64_SEV)
	}
	if (vals[0] & MSR_AMD64_SEV_ENABLED) == MSR_AMD64_SEV_ENABLED {
		log.Debugf("SEV is enabled (MSR 0xC0010131[0] = 1")
		return true, nil, nil
	}
	return false, fmt.Errorf("feature SEV is not enabled (MSR 0xC0010131[0] != 1"), nil
}

// SEVESEnabled checks if SEV-ES is enabled by reading MSR 0xC0010131[1]
func SEVGuestSEVESEnabled(hw hwapi.LowLevelHardwareInterfaces, p *PreSet) (bool, error, error) {
	vals := hw.ReadMSR(MSR_AMD64_SEV)
	if len(vals) == 0 {
		return false, nil, fmt.Errorf("ReadMSR returned no values for SEV MSR")
	}

	if (vals[0] & MSR_AMD64_SEV_ES_ENABLED) == MSR_AMD64_SEV_ES_ENABLED {
		log.Debugf("SEV-ES is enabled (MSR 0xC0010131[1] = 1)")
		return true, nil, nil
	}
	return false, fmt.Errorf("feature not enabled: SEV-ES(MSR 0xC0010131[1] = 0)"), nil
}

// SEVGuestConfig validates SEV guest configuration
func SEVGuestConfig(hw hwapi.LowLevelHardwareInterfaces, p *PreSet) (bool, error, error) {
	log.Info("SEV Guest Configuration check is not implemented")
	return true, nil, nil
}
