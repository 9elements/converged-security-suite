package api

import (
	"github.com/intel-go/cpuid"
)

// #include <stdint.h>
//
// uint64_t readCR4(void) {
//   uint64_t ret;
//
//   asm("movq %%cr4, %0\n" :"=r"(ret));
//   return ret;
// }
import "C"

func SMXIsEnabled() bool {
	cr4 := C.readCR4()

	return cr4&1<<13 != 0
}

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
