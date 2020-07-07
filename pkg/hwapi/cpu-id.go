package hwapi

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

func (t TxtAPI) VersionString() string {
	return cpuid.VendorIdentificatorString
}

func (t TxtAPI) HasSMX() bool {
	return cpuid.HasFeature(cpuid.SMX)
}

func (t TxtAPI) HasVMX() bool {
	return cpuid.HasFeature(cpuid.VMX)
}

func (t TxtAPI) HasMTRR() bool {
	return cpuid.HasFeature(cpuid.MTRR) || cpuid.HasExtraFeature(cpuid.MTRR_2)
}

func (t TxtAPI) ProcessorBrandName() string {
	return cpuid.ProcessorBrandString
}

func (t TxtAPI) CPUSignature() uint32 {
	return uint32(C.cpuid_leaf1_eax())
}

func (t TxtAPI) CPULogCount() uint32 {
	return uint32(cpuid.MaxLogocalCPUId)
}
