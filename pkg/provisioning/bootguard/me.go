package bootguard

import (
	"fmt"

	"github.com/9elements/converged-security-suite/v2/pkg/tools"
	"github.com/9elements/go-linux-lowlevel-hw/pkg/hwapi"
	"github.com/linuxboot/fiano/pkg/intel/metadata/common/bgheader"
)

const (
	// Intel ME Config Space access
	IntelCSMEDeviceID = 16
	IntelSPSDeviceID  = 22
	IntelBus          = 0
	IntelFunction     = 0

	// Boot Guard MSR
	BootGuardACMInfoMSR = 0x13a

	// Error Enforcement Policy
	EnforcementPolicyDoNothing               = 0
	EnforcementPolicyShutdownSomehow         = 2
	EnforcementPolicyShutdownImmediately     = 3
	EnforcementPolicyShutdownInThirtyMinutes = 1
)

type BGInfo struct {
	NEMEnabled              bool
	TPMType                 uint64
	TPMSuccess              bool
	ForceAnchorBoot         bool
	Measured                bool
	Verified                bool
	ModuleRevoked           bool
	BootGuardCapability     bool
	ServerTXTCapability     bool
	NoResetSecretProtection bool
}

// GetBGInfo reads Boot Guard msr during runtime
func GetBGInfo(hw hwapi.LowLevelHardwareInterfaces) (*BGInfo, error) {
	msr := hw.ReadMSR(BootGuardACMInfoMSR)
	if msr == nil {
		return nil, fmt.Errorf("can't read Boot Guard msr")
	}
	var bgi BGInfo
	bgi.NEMEnabled = (msr[0]>>0)&1 != 0
	bgi.TPMType = (msr[0] >> 1) & 3
	bgi.TPMSuccess = (msr[0]>>3)&1 != 0
	bgi.ForceAnchorBoot = (msr[0]>>4)&1 != 0
	bgi.Measured = (msr[0]>>5)&1 != 0
	bgi.Verified = (msr[0]>>6)&1 != 0
	bgi.ModuleRevoked = (msr[0]>>7)&1 != 0
	bgi.BootGuardCapability = (msr[0]>>32)&1 != 0
	bgi.ServerTXTCapability = (msr[0]>>34)&1 != 0
	bgi.NoResetSecretProtection = (msr[0]>>35)&1 != 0
	return &bgi, nil
}

func StrictSaneBootGuardProvisioning(v bgheader.BootGuardVersion, fws *FirmwareStatus6, bgi *BGInfo) (bool, error) {
	if fws.ErrorEnforcementPolicy != EnforcementPolicyShutdownImmediately {
		return false, fmt.Errorf("enforcement policy isn't set to immediate shutdown")
	}

	return SaneMEBootGuardProvisioning(v, fws, bgi)
}

// SaneMEBootGuardProvisioning validates during runtime ME bootguard provisioning
func SaneMEBootGuardProvisioning(v bgheader.BootGuardVersion, fws *FirmwareStatus6, bgi *BGInfo) (bool, error) {
	if fws.BypassBootPolicy {
		return false, fmt.Errorf("bypass boot policy is active")
	}
	if fws.BootPolicyInvalid {
		return false, fmt.Errorf("boot policy is invalid")
	}
	if !fws.FPFLock {
		return false, fmt.Errorf("FPF isn't locked")
	}
	if fws.ErrorEnforcementPolicy == EnforcementPolicyDoNothing ||
		fws.ErrorEnforcementPolicy == EnforcementPolicyShutdownSomehow {
		return false, fmt.Errorf("enforcement policy is lazy and doesn't stop boot process")
	}
	if !fws.ProtectBIOSEnvironment {
		return false, fmt.Errorf("protected bios enviroment is disabled")
	}
	if v == bgheader.Version20 && !bgi.ForceAnchorBoot {
		return false, fmt.Errorf("force anchor boot is disabled")
	}
	if !bgi.Verified {
		return false, fmt.Errorf("verified boot is disabled, measured boot only may be possible but isn't supported by Intel officially")
	}
	if bgi.ModuleRevoked {
		return false, fmt.Errorf("one of the the ACM, BPM and KM may be revoked")
	}
	if fws.BootGuardDisable {
		return false, fmt.Errorf("boot guard is disabled")
	}
	if !bgi.BootGuardCapability {
		return false, fmt.Errorf("missing boot guard microcode updates in FIT")
	}
	return true, nil
}

func ValidTXTRegister(hw hwapi.LowLevelHardwareInterfaces) (bool, error) {
	txtSpace, err := tools.FetchTXTRegs(hw)
	if err != nil {
		return false, fmt.Errorf("couldn't fetch TXT regs: %v", err)
	}

	ACMStatus, err := tools.ReadACMStatus(txtSpace)
	if err != nil {
		return false, fmt.Errorf("couldn't read ACM status: %v", err)
	}

	if !ACMStatus.Valid {
		return false, fmt.Errorf("ACM status is invalid")
	}

	if !ACMStatus.ACMStarted {
		return false, fmt.Errorf("ACM isn't started")
	}

	ACMStatusPolicy, err := tools.ReadACMPolicyStatusRaw(txtSpace)
	if err != nil {
		return false, fmt.Errorf("couldn't read ACM policy status: %v", err)
	}

	if ((ACMStatusPolicy >> 6) & 0x1) != 0 {
		return false, fmt.Errorf("HAP Bit is set")
	}

	Bootstatus, err := tools.ReadBootStatusRaw(txtSpace)
	if err != nil {
		return false, fmt.Errorf("couldn't read bootstatus: %v", err)
	}

	if ((Bootstatus >> 31) & 0x1) != 1 {
		return false, fmt.Errorf("BootGuard did not startup successfully")
	}

	return true, nil
}
