package test

import (
	"fmt"

	"github.com/9elements/go-linux-lowlevel-hw/pkg/hwapi"
	log "github.com/sirupsen/logrus"
)

var (
	TestsTSME = []*Test{
		&testTSMESupport,
		&testTSMEEnabled,
	}
)

// TSMESupport checks if TSME is supported
func TSMESupport(hw hwapi.LowLevelHardwareInterfaces, p *PreSet) (bool, error, error) {
	eax, _, _, _ := hw.CPUID(CPUID_SME_SEV, 0)
	if (eax & CPUID_TSME_SUPPORT) == CPUID_TSME_SUPPORT {
		log.Debugf("TSME is supported (CPUID.0x8000001F[EAX].bit[13] = 1)")
		return true, nil, nil
	}
	return false, fmt.Errorf("TSME is not supported on this CPU (CPUID.0x8000001F[EAX].bit[13] = 0)"), nil
}

// TSMEEnabled checks if TSME is enabled
func TSMEEnabled(hw hwapi.LowLevelHardwareInterfaces, p *PreSet) (bool, error, error) {
	vals := hw.ReadMSR(MSR_AMD64_SYSCFG)
	if len(vals) == 0 {
		return false, nil, fmt.Errorf("ReadMSR returned no values")
	}
	val := vals[0]
	if (val & MSR_AMD64_SYSCFG_TSME_EN) == MSR_AMD64_SYSCFG_TSME_EN {
		log.Debugf("TSME is enabled (MSR 0xC0010010[18] = 1)")
		return true, nil, nil
	}
	return false, fmt.Errorf("TSME is not enabled (MSR 0xC0010010[18] = 0)"), nil
}
