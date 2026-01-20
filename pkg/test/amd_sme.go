package test

import (
	"fmt"
	"os"
	"strings"

	"github.com/9elements/go-linux-lowlevel-hw/pkg/hwapi"
	log "github.com/sirupsen/logrus"
)

var (
	TestsAMDSME = []*Test{
		&testSMESupport,
		&testSMEEnabled,
		&testSMEKernelOption,
		&testTSMESupport,
		&testTSMEEnabled,
	}
)

// SME Tests

// SMESupport checks if SME is supported by the processor
func SMESupport(hw hwapi.LowLevelHardwareInterfaces, p *PreSet) (bool, error, error) {
	eax, _, _, _ := hw.CPUID(CPUID_SME_SEV, 0)
	if (eax & CPUID_SME_SUPPORT) == CPUID_SME_SUPPORT {
		log.Debugf("SME is supported (CPUID.0x8000001F[EAX].bit[0] = 1)")
		return true, nil, nil
	}

	return false, fmt.Errorf("SME is not supported on this CPU (CPUID.0x8000001F[EAX].bit[0] = 0)"), nil
}

// SMEEnabled checks if SME is enabled via BIOS config
func SMEEnabled(hw hwapi.LowLevelHardwareInterfaces, p *PreSet) (bool, error, error) {
	vals := hw.ReadMSR(MSR_AMD64_SYSCFG)
	if len(vals) == 0 {
		return false, nil, fmt.Errorf("reading MSRs returned no values")
	}
	if (vals[0] & MSR_AMD64_SYSCFG_SME_ENABLE) == MSR_AMD64_SYSCFG_SME_ENABLE {
		log.Debugf("SME is enabled (MSR 0xC0010010[23] = 1)")
		return true, nil, nil
	}
	return false, fmt.Errorf("SME is not enabled (MSR 0xC0010010[23] = 0)"), nil
}

// SMEKernelOption checks if SME is activated via kernel commandline option
func SMEKernelOption(hw hwapi.LowLevelHardwareInterfaces, p *PreSet) (bool, error, error) {
	data, err := os.ReadFile("/proc/cmdline")
	if err != nil {
		return false, nil, fmt.Errorf("failed to read /proc/cmdline: %v", err)
	}
	cmdline := string(data)
	log.Debugf("Linux Kernel Commandline: %s", cmdline)
	if strings.Contains(cmdline, "mem_encrypt=on") {
		log.Debugf("SME kernel option 'mem_encrypt=on' is set in kernel command line")
		return true, nil, nil
	}
	return false, fmt.Errorf("SME kernel option 'mem_encrypt=on' is not set in kernel command line"), nil
}
