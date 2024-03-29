package registers

import (
	"fmt"
	"runtime"

	"github.com/9elements/converged-security-suite/v2/pkg/errors"
	"github.com/fearful-symmetry/gomsr"
)

// MSRReader reads a single MSR register
type MSRReader interface {
	// Read reads a single MSR register, the returned value is not length, but
	// the value itself.
	Read(msr int64) (uint64, error)
}

// DefaultMSRReader reads MSR registers from local host.
type DefaultMSRReader struct{}

func readMSRFromCpu(msr int64, cpu int) (uint64, error) {
	msrCtx, err := gomsr.MSR(cpu)
	if err != nil {
		return 0, fmt.Errorf("MSR: Selected core %d doesn't exist (%w)", cpu, err)
	}
	defer msrCtx.Close()

	return msrCtx.Read(msr)
}

// Read reads a single MSR register, the returned value is not length, but
// the value itself.
func (r *DefaultMSRReader) Read(msr int64) (uint64, error) {
	var data uint64
	for i := 0; i < runtime.NumCPU(); i++ {
		msrData, err := readMSRFromCpu(msr, i)
		if err != nil {
			return 0, err
		}
		if i != 0 {
			if data != msrData {
				return 0, fmt.Errorf("MSR: cores of MSR 0x%x non equal", msr)
			}
		}
		data = msrData
	}
	return data, nil
}

type supportedMSRRegister struct {
	id    RegisterID
	fetch func(msrReader MSRReader) (Register, error)
}

var supportedMSRRegistersIDs = []supportedMSRRegister{
	{
		id: BootGuardPBECRegisterID,
		fetch: func(msrReader MSRReader) (Register, error) {
			return ReadBootGuardPBEC(msrReader)
		},
	},
	{
		id: BTGSACMInfoRegisterID,
		fetch: func(msrReader MSRReader) (Register, error) {
			return ReadBTGSACMInfo(msrReader)
		},
	},
	{
		id: IA32DebugInterfaceRegisterID,
		fetch: func(msrReader MSRReader) (Register, error) {
			return ReadIA32DebugInterface(msrReader)
		},
	},
	{
		id: IA32FeatureControlRegisterID,
		fetch: func(msrReader MSRReader) (Register, error) {
			return ReadIA32FeatureControl(msrReader)
		},
	},
	{
		id: IA32MTRRCAPRegisterID,
		fetch: func(msrReader MSRReader) (Register, error) {
			return ReadIA32MTRRCAP(msrReader)
		},
	},
	{
		id: IA32PlatformIDRegisterID,
		fetch: func(msrReader MSRReader) (Register, error) {
			return ReadIA32PlatformID(msrReader)
		},
	},
	{
		id: IA32SMRRPhysBaseRegisterID,
		fetch: func(msrReader MSRReader) (Register, error) {
			return ReadIA32SMRRPhysBase(msrReader)
		},
	},
	{
		id: IA32SMRRPhysMaskRegisterID,
		fetch: func(msrReader MSRReader) (Register, error) {
			return ReadIA32SMRRPhysMask(msrReader)
		},
	},
}

// ReadMSRRegisters fetches all supported MSR registers
func ReadMSRRegisters(msrReader MSRReader) (Registers, error) {
	var result Registers
	var mErr errors.MultiError

	for _, registerInfo := range supportedMSRRegistersIDs {
		reg, err := registerInfo.fetch(msrReader)
		if err != nil {
			_ = mErr.Add(fmt.Errorf("failed to fetch MSR register %s, err: %v", registerInfo.id, err))
			continue
		}
		result = append(result, reg)
	}

	if mErr.Count() > 0 {
		return result, mErr
	}
	return result, nil
}
