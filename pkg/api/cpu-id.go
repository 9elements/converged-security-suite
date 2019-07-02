package api

import (
	"github.com/intel-go/cpuid"
)

// #include <stdint.h>
//
// uint64_t getSecCapability(void) {
//   uint64_t ret;
//
//   asm volatile(
//		"movq $0, %%rax\n"
//		"getsec\n"
//		"movq %%rbx, %0\n"
//    :"=r"(ret) : : "rax", "rbx" );
//   return ret;
// }
import "C"

func ChipsetHasTXT() bool {
	return C.getSecCapability()&1 == 1
}

func HasTXTLeaves() bool {
	enterAccs := 1 << 1
	exitAc := 1 << 2
	senter := 1 << 3
	sexit := 1 << 4
	leaves := C.uint64_t(enterAccs | exitAc | senter | sexit)

	return C.getSecCapability()&leaves == leaves
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
