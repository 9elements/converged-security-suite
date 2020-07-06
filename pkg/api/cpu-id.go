package api

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
import "github.com/intel-go/cpuid"

func (t TxtApi) VersionString() string {
	return cpuid.VendorIdentificatorString
}

func (t TxtApi) HasSMX() bool {
	return cpuid.HasFeature(cpuid.SMX)
}

func (t TxtApi) HasVMX() bool {
	return cpuid.HasFeature(cpuid.VMX)
}

func (t TxtApi) HasMTRR() bool {
	return cpuid.HasFeature(cpuid.MTRR) || cpuid.HasExtraFeature(cpuid.MTRR_2)
}

func (t TxtApi) ProcessorBrandName() string {
	return cpuid.ProcessorBrandString
}

func (t TxtApi) CPUSignature() uint32 {
	return uint32(C.cpuid_leaf1_eax())
}

func (t TxtApi) CPULogCount() uint32 {
	return uint32(cpuid.MaxLogocalCPUId)
}
