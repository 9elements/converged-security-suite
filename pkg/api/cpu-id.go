package api

import (
	"github.com/intel-go/cpuid"
)

func VersionString() string {
	return cpuid.VendorIdentificatorString
}

func WeybridgeOrLater() bool {
	return cpuid.DisplayFamily == 6
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
