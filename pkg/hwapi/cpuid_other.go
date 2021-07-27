// +build !amd64

// Package hwapi provides access to low level hardware
package hwapi

//VersionString returns the vendor ID
func (t TxtAPI) VersionString() string {
	return "null"
}

//HasSMX returns true if SMX is supported
func (t TxtAPI) HasSMX() bool {
	return false
}

//HasVMX returns true if VMX is supported
func (t TxtAPI) HasVMX() bool {
	return false
}

//HasMTRR returns true if MTRR are supported
func (t TxtAPI) HasMTRR() bool {
	return false
}

//ProcessorBrandName returns the CPU brand name
func (t TxtAPI) ProcessorBrandName() string {
	return "not intel"
}

//CPUSignature returns CPUID=1 eax
func (t TxtAPI) CPUSignature() uint32 {
	return 0
}

//CPULogCount returns number of logical CPU cores
func (t TxtAPI) CPULogCount() uint32 {
	return 0
}
