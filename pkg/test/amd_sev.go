package test

import (
	"fmt"
	"os"
	"strings"

	"github.com/9elements/go-linux-lowlevel-hw/pkg/hwapi"
	log "github.com/sirupsen/logrus"
	"golang.org/x/sys/unix"
)

var (
	TestsAMDSEV = []*Test{
		&testSEVSupport,
		&testSEVEnabledInSysFS,
		&testSEVFirmwareVersion,
	}
)

// SEVSupport checks if SEV is supported by checking CPUID[0x8000001f].EAX[1]
func SEVSupport(hw hwapi.LowLevelHardwareInterfaces, p *PreSet) (bool, error, error) {
	eax, _, _, _ := hw.CPUID(CPUID_SME_SEV, 0)
	if (eax & CPUID_SEV_SUPPORT) == CPUID_SEV_SUPPORT {
		log.Debugf("SEV is supported (CPUID.0x8000001F[EAX].bit[1] = 1)")
		return true, nil, nil
	}
	return false, fmt.Errorf("SEV is not supported on this CPU (CPUID.0x8000001F[EAX].bit[1] != 1)"), nil
}

func SEVEnabledInSysFS(hw hwapi.LowLevelHardwareInterfaces, p *PreSet) (bool, error, error) {
	data, err := os.ReadFile("/sys/module/kvm_amd/parameters/sev")
	if err != nil {
		return false, nil, err
	}

	if strings.TrimSpace(string(data)) == "Y" {
		return true, nil, nil
	}

	return false, fmt.Errorf("feature SEV not enabled in SysFS path: /sys/module/kvm_amd/parameters/sev != Y"), nil
}

// SEVFirmwareVersion validates SEV firmware version
func SEVFirmwareVersion(hw hwapi.LowLevelHardwareInterfaces, p *PreSet) (bool, error, error) {
	var buf strings.Builder
	splitString := "SEV API:"
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
		log.Infof("SEV API Version found: %s", l[1])
		return true, nil, nil
	}
	return false, fmt.Errorf("no log with string 'SEV API:' found"), nil
}
