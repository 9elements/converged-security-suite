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

func ProcessorBrandName() string {
	return cpuid.ProcessorBrandString
}
