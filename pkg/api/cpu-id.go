package api

import (
	"github.com/intel-go/cpuid"
)

func VersionString() string {
	return cpuid.VendorIdentificatorString
}

func HasSMX() bool {
	return cpuid.HasFeature(cpuid.SMX)
}

func HasVMX() bool {
	return cpuid.HasFeature(cpuid.VMX)
}

func HasMTRR() bool {
	return cpuid.HasFeature(cpuid.MTRR) && cpuid.HasExtraFeature(cpuid.MTRR_2)
}

func ProcessorBrandName() string {
	return cpuid.ProcessorBrandString
}

func FamilyModelStepping() uint32 {
	f := cpuid.DisplayFamily << 8
	m := cpuid.DisplayModel << 4
	s := cpuid.SteppingId

	return f | m | s
}
