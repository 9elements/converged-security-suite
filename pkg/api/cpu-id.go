package api

import (
	"github.com/intel-go/cpuid"
)

// #include <stdint.h>
//
// uint32_t cpuid_leaf1_eax(void) {
//   uint32_t ret = 0;
//
//   asm volatile(
//     "movl $1, %%eax\n"
//     "movl $0, %%ecx\n"
//     "cpuid\n"
//     "movl %%eax, %0\n"
//     : "=m"(ret)
//     :
//     : "eax", "ebx", "ecx", "edx");
//
//   return ret;
// }
import "C"

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

func CPUSignature() uint32 {
	return uint32(C.cpuid_leaf1_eax())
}
