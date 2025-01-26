package test

import (
	"fmt"
	"os"
	"strings"

	"github.com/9elements/go-linux-lowlevel-hw/pkg/hwapi"
	log "github.com/sirupsen/logrus"
)

var (
	testSEVESupport = Test{
		Name:                 "SEV-ES Support",
		Required:             true,
		function:             SEVESSupport,
		Status:               Implemented,
		SpecificationChapter: "",
		SpecificiationTitle:  "AMD Secure Encrypted Virtualization - Encrypted State",
		dependencies:         []*Test{&testAMDFamilyModel},
	}

	testSEVESEnabledinSysFS = Test{
		Name:                 "SEV-ES Enabled in BIOS",
		Required:             true,
		function:             SEVESInSysFSEnabled,
		Status:               Implemented,
		SpecificationChapter: "",
		SpecificiationTitle:  "AMD Secure Encrypted Virtualization - Encrypted State",
		dependencies:         []*Test{&testAMDFamilyModel},
	}

	TestsSEVES = []*Test{
		&testSEVESupport,
		&testSEVESEnabledinSysFS,
	}
)

// SEV-ES Tests
func SEVESSupport(hw hwapi.LowLevelHardwareInterfaces, p *PreSet) (bool, error, error) {
	// Check CPUID
	eax, _, _, _ := hw.CPUID(CPUID_SME_SEV, 0)
	if (eax & CPUID_SEV_ES_SUPPORT) == CPUID_SEV_ES_SUPPORT {
		return true, nil, nil
	}
	return false, fmt.Errorf("SEV-ES is not supported (CPUID.0x8000001F[EAX].bit[3] = 1"), nil
}

func SEVESInSysFSEnabled(hw hwapi.LowLevelHardwareInterfaces, p *PreSet) (bool, error, error) {
	data, err := os.ReadFile("/sys/module/kvm_amd/parameters/sev_es")
	if err != nil {
		return false, nil, err
	}

	if strings.TrimSpace(string(data)) == "Y" {
		log.Debugf("SEV-ES marked enabled in '/sys/module/kvm_amd/parameters/sev_es' = Y)")
		return true, nil, nil
	}
	return false, fmt.Errorf("SEV-ES marked disabled in '/sys/module/kvm_amd/parameters/sev_es' = N)"), nil
}
