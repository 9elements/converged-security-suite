package bootguard

import (
	"encoding/binary"
	"fmt"

	"github.com/9elements/go-linux-lowlevel-hw/pkg/hwapi"
)

// Const Array with HFSTS Offsets
var hfstsOffset = []int{0x40, 0x48, 0x60, 0x64, 0x68, 0x6c}

type FirmwareStatus struct {
	// ME 16
	Status1 *FirmwareStatus1
	Status6 *FirmwareStatus6
	// ME 18/21
	Status5 *FirmwareStatus5
}

func NewFirmwareStatus(hw hwapi.LowLevelHardwareInterfaces) (*FirmwareStatus, error) {
	// ME 16
	hwsts1v16, err := getHFSTS1(hw)
	if err != nil {
		return nil, err
	}

	hwsts6, err := getHFSTS6(hw)
	if err != nil {
		return nil, err
	}

	hwsts5, err := getHFSTS5(hw)
	if err != nil {
		return nil, err
	}

	return &FirmwareStatus{
		// ME 16
		Status1: hwsts1v16,
		Status6: hwsts6,
		// ME 18/21
		Status5: hwsts5,
	}, nil
}

type FirmwareStatus1 struct {
	WorkingState       uint32
	MfgMode            bool
	FPTBad             bool
	OperatingState     uint32
	FWInitComplete     bool
	FTBUPLoaded        bool
	FWUpdateInProgress bool
	ErrorCode          uint32
	OperatingMode      uint32
	ResetCount         uint32
	BootOptionPresent  bool
	BISTFinished       bool
	BISTTestState      bool
	BISTResetRequest   bool
}

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

func getHFSTS1(hw hwapi.LowLevelHardwareInterfaces) (*FirmwareStatus1, error) {
	hfsts1, err := readHFSTSFromPCIConfigSpace(hw, 1)
	if err != nil {
		return nil, fmt.Errorf("couldn't read HFSTS6 from PCI config space: %v", err)
	}

	firmwareStatus := FirmwareStatus1{}

	configSpace := binary.LittleEndian.Uint32(hfsts1)

	firmwareStatus.WorkingState = (configSpace >> 0) & 15
	firmwareStatus.MfgMode = (configSpace>>4)&1 != 0
	firmwareStatus.FPTBad = (configSpace>>5)&1 != 0
	firmwareStatus.OperatingState = (configSpace >> 6) & 7
	firmwareStatus.FWInitComplete = (configSpace>>9)&1 != 0
	firmwareStatus.FTBUPLoaded = (configSpace>>10)&1 != 0
	firmwareStatus.FWUpdateInProgress = (configSpace>>11)&1 != 0
	firmwareStatus.ErrorCode = (configSpace >> 12) & 15
	firmwareStatus.OperatingMode = (configSpace >> 16) & 15
	firmwareStatus.ResetCount = (configSpace >> 20) & 15
	firmwareStatus.BootOptionPresent = (configSpace>>24)&1 != 0
	firmwareStatus.BISTFinished = (configSpace>>25)&1 != 0
	firmwareStatus.BISTTestState = (configSpace>>26)&1 != 0
	firmwareStatus.BISTResetRequest = (configSpace>>27)&1 != 0

	return &firmwareStatus, nil
}

func getHFSTS6(hw hwapi.LowLevelHardwareInterfaces) (*FirmwareStatus6, error) {
	hfsts6, err := readHFSTSFromPCIConfigSpace(hw, 6)
	if err != nil {
		return nil, fmt.Errorf("couldn't read HFSTS6 from PCI config space: %v", err)
	}

	firmwareStatus := FirmwareStatus6{}

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

type FirmwareStatus5 struct {
	BgACMStatus      bool
	VLD              bool
	RCS              bool
	ErrorCode        uint32
	TXTSupported     bool
	CPUDebugDisabled bool
	BSPInitDisabled  bool
	BPMExecStatus    bool
	BgStatus         uint32
}

// ME 18/21
func getHFSTS5(hw hwapi.LowLevelHardwareInterfaces) (*FirmwareStatus5, error) {
	hfsts5, err := readHFSTSFromPCIConfigSpace(hw, 5)
	if err != nil {
		return nil, fmt.Errorf("couldn't read HFSTS5 from PCI config space: %v", err)
	}

	firmwareStatus := FirmwareStatus5{}

	configSpace := binary.LittleEndian.Uint32(hfsts5)
	firmwareStatus.BgACMStatus = (configSpace>>0)&1 != 0
	firmwareStatus.VLD = (configSpace>>1)&1 != 0
	firmwareStatus.RCS = (configSpace>>2)&1 != 0
	firmwareStatus.ErrorCode = (configSpace >> 3) & 31
	firmwareStatus.TXTSupported = (configSpace>>17)&1 != 0
	firmwareStatus.CPUDebugDisabled = (configSpace>>21)&1 != 0
	firmwareStatus.BSPInitDisabled = (configSpace>>22)&1 != 0
	firmwareStatus.BPMExecStatus = (configSpace>>23)&1 != 0
	firmwareStatus.BgStatus = (configSpace >> 25) & 15

	return &firmwareStatus, nil
}

func readHFSTSFromPCIConfigSpace(hw hwapi.LowLevelHardwareInterfaces, offset int) ([]byte, error) {
	if offset < 1 || offset > 6 {
		return nil, fmt.Errorf("invalid HFSTS offset")
	}

	var err error
	hfsts := make([]byte, 4)
	if err := hw.PCIEnumerateVisibleDevices(
		func(d hwapi.PCIDevice) (abort bool) {
			if (d.Device == IntelCSMEDeviceID && d.Function == IntelFunction) ||
				(d.Device == IntelSPSDeviceID && d.Function == IntelFunction) {
				hfsts, err = hw.PCIReadConfigSpace(d, hfstsOffset[offset-1], len(hfsts))
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

	return hfsts, nil
}
