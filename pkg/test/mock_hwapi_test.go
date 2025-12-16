package test

import (
	"github.com/9elements/go-linux-lowlevel-hw/pkg/hwapi"
	"github.com/digitalocean/go-smbios/smbios"
)

// MockHardwareAPI implements hwapi.LowLevelHardwareInterfaces for testing
type MockHardwareAPI struct {
	CPUIDFunc        func(eax, ecx uint32) (uint32, uint32, uint32, uint32)
	ReadMSRFunc      func(msr int64) []uint64
	ReadPhysBufFunc  func(addr int64, buf []byte) error
	VersionStringFunc func() string
	CPUSignatureFunc  func() uint32
}

// Ensure MockHardwareAPI implements the interface
var _ hwapi.LowLevelHardwareInterfaces = (*MockHardwareAPI)(nil)

func (m *MockHardwareAPI) CPUID(eax, ecx uint32) (uint32, uint32, uint32, uint32) {
	if m.CPUIDFunc != nil {
		return m.CPUIDFunc(eax, ecx)
	}
	return 0, 0, 0, 0
}

func (m *MockHardwareAPI) ReadMSR(msr int64) []uint64 {
	if m.ReadMSRFunc != nil {
		return m.ReadMSRFunc(msr)
	}
	return []uint64{}
}

func (m *MockHardwareAPI) ReadPhysBuf(addr int64, buf []byte) error {
	if m.ReadPhysBufFunc != nil {
		return m.ReadPhysBufFunc(addr, buf)
	}
	return nil
}

func (m *MockHardwareAPI) VersionString() string {
	if m.VersionStringFunc != nil {
		return m.VersionStringFunc()
	}
	return ""
}

func (m *MockHardwareAPI) CPUSignature() uint32 {
	if m.CPUSignatureFunc != nil {
		return m.CPUSignatureFunc()
	}
	return 0
}

// Implement other required interface methods as no-ops or minimal implementations

// cpuid.go methods
func (m *MockHardwareAPI) HasSMX() bool {
	return false
}

func (m *MockHardwareAPI) HasVMX() bool {
	return false
}

func (m *MockHardwareAPI) HasMTRR() bool {
	return false
}

func (m *MockHardwareAPI) ProcessorBrandName() string {
	return ""
}

func (m *MockHardwareAPI) CPUSignatureFull() (uint32, uint32, uint32, uint32) {
	return 0, 0, 0, 0
}

func (m *MockHardwareAPI) CPULogCount() uint32 {
	return 1
}

// e820.go methods
func (m *MockHardwareAPI) IterateOverE820Ranges(_ string, _ func(start uint64, end uint64) bool) (bool, error) {
	return false, nil
}

// iommu.go methods
func (m *MockHardwareAPI) LookupIOAddress(_ uint64, _ hwapi.VTdRegisters) ([]uint64, error) {
	return nil, nil
}

// phys.go methods
func (m *MockHardwareAPI) ReadPhys(_ int64, _ hwapi.UintN) error {
	return nil
}

func (m *MockHardwareAPI) WritePhys(_ int64, _ hwapi.UintN) error {
	return nil
}

// pci.go methods
func (m *MockHardwareAPI) PCIEnumerateVisibleDevices(_ func(d hwapi.PCIDevice) (abort bool)) error {
	return nil
}

func (m *MockHardwareAPI) PCIReadConfigSpace(_ hwapi.PCIDevice, _ int, _ int) ([]byte, error) {
	return nil, nil
}

func (m *MockHardwareAPI) PCIWriteConfigSpace(_ hwapi.PCIDevice, _ int, _ interface{}) error {
	return nil
}

// tpm.go methods
func (m *MockHardwareAPI) NewTPM() (*hwapi.TPM, error) {
	return nil, nil
}

func (m *MockHardwareAPI) NVLocked(_ *hwapi.TPM) (bool, error) {
	return false, nil
}

func (m *MockHardwareAPI) ReadNVPublic(_ *hwapi.TPM, _ uint32) ([]byte, error) {
	return nil, nil
}

func (m *MockHardwareAPI) NVReadValue(_ *hwapi.TPM, _ uint32, _ string, _, _ uint32) ([]byte, error) {
	return nil, nil
}

func (m *MockHardwareAPI) ReadPCR(_ *hwapi.TPM, _ uint32) ([]byte, error) {
	return nil, nil
}

// acpi.go methods
func (m *MockHardwareAPI) GetACPITable(_ string) ([]byte, error) {
	return nil, nil
}

// smbios.go methods
func (m *MockHardwareAPI) IterateOverSMBIOSTables(_ uint8, _ func(s *smbios.Structure) bool) (ret bool, err error) {
	return false, nil
}
