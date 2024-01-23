package bootguard

import (
	"encoding/binary"
	"fmt"

	"github.com/9elements/go-linux-lowlevel-hw/pkg/hwapi"
	"github.com/linuxboot/fiano/pkg/intel/metadata/common/bgheader"
)

const (
	// Intel ME Config Space access
	IntelCSMEDeviceID = 16
	IntelSPSDeviceID  = 22
	IntelBus          = 0
	IntelFunction     = 0
	hfsts6Offset      = 0x6c

	// Boot Guard MSR
	BootGuardACMInfoMSR = 0x13a

	// Error Enforcement Policy
	EnforcementPolicyDoNothing               = 0
	EnforcementPolicyShutdownSomehow         = 2
	EnforcementPolicyShutdownImmediately     = 3
	EnforcementPolicyShutdownInThirtyMinutes = 1
)

type FirmwareStatus6 struct {
	ForceACMBootPolicy                bool
	CPUDebugDisabled                  bool
	BSPInitDisabled                   bool
	ProtectBIOSEnvironment            bool
	BypassBootPolicy                  bool
	BootPolicyInvalid                 bool
	ErrorEnforcementPolicy            uint32
	MeasuredBootPolicy                bool
	VerifiedBootPolicy                bool
	ACMSVN                            uint32
	KMSVN                             uint32
	BPMSVN                            uint32
	KMID                              uint32
	BootPolicyManifestExecutionStatus bool
	Error                             bool
	BootGuardDisable                  bool
	FPFDisable                        bool
	FPFLock                           bool
	TXTSupported                      bool
}

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

// GetMEInfo reads bootguard provisioning information from Intel ME
func GetMEInfo(hw hwapi.LowLevelHardwareInterfaces) (*FirmwareStatus6, error) {
	var err error
	hfsts6 := make([]byte, 4)
	if err := hw.PCIEnumerateVisibleDevices(
		func(d hwapi.PCIDevice) (abort bool) {
			if (d.Device == IntelCSMEDeviceID && d.Function == IntelFunction) ||
				(d.Device == IntelSPSDeviceID && d.Function == IntelFunction) {
				hfsts6, err = hw.PCIReadConfigSpace(d, hfsts6Offset, len(hfsts6))
				if err != nil {
					return true
				}
				return true
			}
			return false
		}); err != nil {
		return nil, fmt.Errorf("couldn't enumerate PCI devices")
	}
	if err != nil {
		return nil, fmt.Errorf("couldn't find Intel ME device for runtime checks")
	}
	var firmwareStatus FirmwareStatus6
	configSpace := binary.LittleEndian.Uint32(hfsts6)
	firmwareStatus.ForceACMBootPolicy = (configSpace>>0)&1 != 0
	firmwareStatus.CPUDebugDisabled = (configSpace>>1)&1 != 0
	firmwareStatus.BSPInitDisabled = (configSpace>>2)&1 != 0
	firmwareStatus.ProtectBIOSEnvironment = (configSpace>>3)&1 != 0
	firmwareStatus.BypassBootPolicy = (configSpace>>4)&1 != 0
	firmwareStatus.BootPolicyInvalid = (configSpace>>5)&1 != 0
	firmwareStatus.ErrorEnforcementPolicy = (configSpace >> 6) & 3
	firmwareStatus.MeasuredBootPolicy = (configSpace>>8)&1 != 0
	firmwareStatus.VerifiedBootPolicy = (configSpace>>9)&1 != 0
	firmwareStatus.ACMSVN = (configSpace >> 10) & 15
	firmwareStatus.KMSVN = (configSpace >> 14) & 15
	firmwareStatus.BPMSVN = (configSpace >> 18) & 15
	firmwareStatus.KMID = (configSpace >> 22) & 15
	firmwareStatus.BootPolicyManifestExecutionStatus = (configSpace>>26)&1 != 0
	firmwareStatus.Error = (configSpace>>27)&1 != 0
	firmwareStatus.BootGuardDisable = (configSpace>>28)&1 != 0
	firmwareStatus.FPFDisable = (configSpace>>29)&1 != 0
	firmwareStatus.FPFLock = (configSpace>>30)&1 != 0
	firmwareStatus.TXTSupported = (configSpace>>31)&1 != 0
	return &firmwareStatus, nil
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
