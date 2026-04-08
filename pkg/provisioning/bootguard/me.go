package bootguard

import (
	"fmt"

	"github.com/9elements/converged-security-suite/v2/pkg/tools"
	"github.com/9elements/go-linux-lowlevel-hw/pkg/hwapi"
	"github.com/linuxboot/fiano/pkg/intel/metadata/cbnt"
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
	var bgi BGInfo
	bgi.NEMEnabled = (msr>>0)&1 != 0
	bgi.TPMType = (msr >> 1) & 3
	bgi.TPMSuccess = (msr>>3)&1 != 0
	bgi.ForceAnchorBoot = (msr>>4)&1 != 0
	bgi.Measured = (msr>>5)&1 != 0
	bgi.Verified = (msr>>6)&1 != 0
	bgi.ModuleRevoked = (msr>>7)&1 != 0
	bgi.BootGuardCapability = (msr>>32)&1 != 0
	bgi.ServerTXTCapability = (msr>>34)&1 != 0
	bgi.NoResetSecretProtection = (msr>>35)&1 != 0
	return &bgi, nil
}

func StrictSaneBootGuardProvisioning(v cbnt.BootGuardVersion, fws *FirmwareStatus, bgi *BGInfo) (bool, error) {
	if fws.Status6.ErrorEnforcementPolicy != EnforcementPolicyShutdownImmediately {
		return false, fmt.Errorf("enforcement policy isn't set to immediate shutdown")
	}

	return SaneMEBootGuardProvisioning(v, fws, bgi)
}

// SaneMEBootGuardProvisioning validates during runtime ME bootguard provisioning
func SaneMEBootGuardProvisioning(v cbnt.BootGuardVersion, fws *FirmwareStatus, bgi *BGInfo) (bool, error) {
	ver, err := tools.GetMEVersion()
	if err != nil {
		return false, err
	}
	if !bgi.BootGuardCapability {
		return false, fmt.Errorf("missing boot guard microcode updates in FIT")
	}

	switch ver {
	case tools.Version16:
		if fws.Status6.BypassBootPolicy {
			return false, fmt.Errorf("bypass boot policy is active")
		}
		if fws.Status6.BootPolicyInvalid {
			return false, fmt.Errorf("boot policy is invalid")
		}
		if !fws.Status6.FPFLock {
			return false, fmt.Errorf("FPF isn't locked")
		}
		if fws.Status6.ErrorEnforcementPolicy == EnforcementPolicyDoNothing ||
			fws.Status6.ErrorEnforcementPolicy == EnforcementPolicyShutdownSomehow {
			return false, fmt.Errorf("enforcement policy is lazy and doesn't stop boot process")
		}
		if !fws.Status6.ProtectBIOSEnvironment {
			return false, fmt.Errorf("protected bios enviroment is disabled")
		}
		if v == cbnt.Version20 && !bgi.ForceAnchorBoot {
			return false, fmt.Errorf("force anchor boot is disabled")
		}
		if !bgi.Verified {
			return false, fmt.Errorf("verified boot is disabled, measured boot only may be possible but isn't supported by Intel officially")
		}
		if bgi.ModuleRevoked {
			return false, fmt.Errorf("one of the the ACM, BPM and KM may be revoked")
		}
		if fws.Status6.BootGuardDisable {
			return false, fmt.Errorf("boot guard is disabled")
		}
		if !bgi.BootGuardCapability {
			return false, fmt.Errorf("missing boot guard microcode updates in FIT")
		}
	case tools.Version18, tools.Version21:
		if !fws.Status6.FPFLock {
			return false, fmt.Errorf("FPF is not locked")
		}
		if fws.Status1.MfgMode {
			return false, fmt.Errorf("debug mode is enabled")
		}
		if !fws.Status5.VLD {
			return false, fmt.Errorf("bits that follow are invalid")
		}
		if fws.Status5.RCS {
			return false, fmt.Errorf("RCS does not come from ACM")
		}
		if !fws.Status5.CPUDebugDisabled {
			return false, fmt.Errorf("cpu debug is enabled")
		}
		if fws.Status1.WorkingState != 0x05 {
			return false, fmt.Errorf("invalid working state")
		}
		if fws.Status1.OperatingMode != 0 {
			return false, fmt.Errorf("invalid operating mode")
		}
		if (v == cbnt.Version20 || v == cbnt.Version21) && !bgi.ForceAnchorBoot {
			return false, fmt.Errorf("force anchor boot is disabled")
		}
		if !bgi.Verified {
			return false, fmt.Errorf("verified boot is disabled, measured boot only may be possible but isn't supported by Intel officially")
		}
		if bgi.ModuleRevoked {
			return false, fmt.Errorf("one of the the ACM, BPM and KM may be revoked")
		}
		if fws.Status6.BootGuardDisable {
			return false, fmt.Errorf("boot guard is disabled")
		}
		if !bgi.BootGuardCapability {
			return false, fmt.Errorf("missing boot guard microcode updates in FIT")
		}
	}
	return true, nil
}

func ValidACMStatus(hw hwapi.LowLevelHardwareInterfaces) (bool, error) {
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

	if !Bootstatus.BgSuccess {
		return false, fmt.Errorf("BootGuard did not startup successfully")
	}

	return true, nil
}

func ValidTXTRegisters(hw hwapi.LowLevelHardwareInterfaces) (bool, error) {
	txtSpace, err := tools.FetchTXTRegs(hw)
	if err != nil {
		return false, fmt.Errorf("couldn't fetch TXT regs: %v", err)
	}

	// The check for ACM status by reading txtSpace >> 0x328 only gives a meaningful
	// results if TXT is disabled in BIOS by the user. Otherwise the same address will be
	// used as TXT.ERRORCODE register, and filled with the TXT status. Now given that TXT started
	// successfully, bit 31 will change the meaning, i.e. if set, there is some error that we could
	// further evaluate, otherwise we shall ignore the rest. Thus, let's keep the 'old' logic iff TXT
	// is disabled. The check can be done by reading 15th bit of IA32_FEATURE_CONTROL MSR.
	txtEnabled := hw.ReadMSR(0x3a)

	Bootstatus, err := tools.ReadBootStatusRaw(txtSpace)
	if err != nil {
		return false, fmt.Errorf("couldn't read bootstatus: %v", err)
	}

	if (txtEnabled >> 15) == 0 {
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

	} else {
		if !Bootstatus.TxtSuccess {
			return false, fmt.Errorf("TXT did not startup successfully")
		}
	}

	ACMStatusPolicy, err := tools.ReadACMPolicyStatusRaw(txtSpace)
	if err != nil {
		return false, fmt.Errorf("couldn't read ACM policy status: %v", err)
	}

	if ((ACMStatusPolicy >> 6) & 0x1) != 0 {
		return false, fmt.Errorf("HAP Bit is set")
	}

	if ((ACMStatusPolicy >> 4) & 0x1) != 1 {
		return false, fmt.Errorf("Measured boot is disabled")
	}

	if ((ACMStatusPolicy >> 5) & 0x1) != 1 {
		return false, fmt.Errorf("verified boot is disabled")
	}

	if !Bootstatus.BgSuccess {
		return false, fmt.Errorf("BootGuard did not startup successfully")
	}

	if !Bootstatus.BIOSTrusted {
		return false, fmt.Errorf("bios is not trusted")
	}

	if !Bootstatus.SACMSuccess {
		return false, fmt.Errorf("SACM status invalid")
	}

	if Bootstatus.CPUError {
		return false, fmt.Errorf("CPU error")
	}

	return true, nil
}
