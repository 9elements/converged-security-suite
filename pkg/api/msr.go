package api

import (
	"fmt"

	"github.com/fearful-symmetry/gomsr"
)

//Model specific registers
const (
	msrSMBase   int64 = 0x9e
	msrMTRRCap   int64 = 0xfe
	msrSMRRPhysBase       int64 = 0x1F2
	msrSMRRPhysMask       int64 = 0x1F3
	msrFeatureControl     int64 = 0x3A
	msrPlatformID         int64 = 0x17
	msrIA32DebugInterface int64 = 0xC80
)

func HasSMRR() (bool, error) {
	mtrrcap, err := gomsr.ReadMSR(0, msrMTRRCap)
	if err != nil {
		return false, fmt.Errorf("Cannot access MSR IA32_MTRRCAP: %s", err)
	}

	return (mtrrcap>>11)&1 != 0, nil
}

// MTRR for the SMM code.
type SMRR struct {
	Active   bool
	PhysBase uint64
	PhysMask uint64
}

// Returns SMRR config of the platform
func GetSMRRInfo() (SMRR, error) {
	var ret SMRR

	smrrPhysbase, err := gomsr.ReadMSR(0, msrSMRRPhysBase)
	if err != nil {
		return ret, fmt.Errorf("Cannot access MSR IA32_SMRR_PHYSBASE: %s", err)
	}

	smrrPhysmask, err := gomsr.ReadMSR(0, msrSMRRPhysMask)
	if err != nil {
		return ret, fmt.Errorf("Cannot access MSR IA32_SMRR_PHYSMASK: %s", err)
	}

	ret.Active = (smrrPhysmask>>11)&1 != 0
	ret.PhysBase = (smrrPhysbase >> 12) & 0xfffff
	ret.PhysMask = (smrrPhysmask >> 12) & 0xfffff

	return ret, nil
}

func IA32FeatureControlIsLocked() (bool, error) {
	featCtrl, err := gomsr.ReadMSR(0, msrFeatureControl)
	if err != nil {
		return false, fmt.Errorf("Cannot access MSR IA32_FEATURE_CONTROL: %s", err)
	}

	return featCtrl&1 != 0, nil
}

func IA32PlatformID() (uint64, error) {
	pltID, err := gomsr.ReadMSR(0, msrPlatformID)
	if err != nil {
		return 0, fmt.Errorf("Cannot access MSR IA32_PLATFORM_ID: %s", err)
	}

	return pltID, nil
}

func AllowsVMXInSMX() (bool, error) {
	featCtrl, err := gomsr.ReadMSR(0, msrFeatureControl)
	if err != nil {
		return false, fmt.Errorf("Cannot access MSR IA32_FEATURE_CONTROL: %s", err)
	}

	var mask uint64 = (1 << 1) & (1 << 5) & (1 << 6)
	return (mask & featCtrl) == mask, nil
}

func TXTLeavesAreEnabled() (bool, error) {
	featCtrl, err := gomsr.ReadMSR(0, msrFeatureControl)
	if err != nil {
		return false, fmt.Errorf("Cannot access MSR IA32_FEATURE_CONTROL: %s", err)
	}

	txt_bits := (featCtrl >> 8) & 0x1ff
	return (txt_bits&0xff == 0xff) || (txt_bits&0x100 == 0x100), nil
}

func IA32DebugInterfaceEnabledOrLocked() (bool, bool, bool, error) {
	debugInterfaceCtrl, err := gomsr.ReadMSR(0, msrIA32DebugInterface)
	if err != nil {
		return false, false, false, fmt.Errorf("Cannot access MSR IA32_DEBUG_INTERFACE: %s", err)
	}

	locked := (debugInterfaceCtrl>>0)&1 != 0
	pchStrap := (debugInterfaceCtrl>>30)&1 != 0
	enabled := (debugInterfaceCtrl>>31)&1 != 0
	return locked, pchStrap, enabled, nil
}
