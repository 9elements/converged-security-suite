package hwapi

import (
	"fmt"
	"io"
)

type nullmock struct{}

func (n nullmock) CPUBlacklistTXTSupport() bool {
	return false
}

func (n nullmock) CPUWhitelistTXTSupport() bool {
	return false
}

func (n nullmock) VersionString() string {
	return ""
}

func (n nullmock) HasSMX() bool {
	return false
}

func (n nullmock) HasVMX() bool {
	return false
}

func (n nullmock) HasMTRR() bool {
	return false
}

func (n nullmock) ProcessorBrandName() string {
	return ""
}
func (n nullmock) CPUSignature() uint32 {
	return 0
}
func (n nullmock) CPULogCount() uint32 {
	return 0
}

func (n nullmock) IsReservedInE810(start uint64, end uint64) (bool, error) {
	return false, fmt.Errorf("Not implemented")
}

func (n nullmock) LookupIOAddress(addr uint64, regs VTdRegisters) ([]uint64, error) {
	return []uint64{}, fmt.Errorf("Not implemented")
}

func (n nullmock) AddressRangesIsDMAProtected(first, end uint64) (bool, error) {
	return false, fmt.Errorf("Not implemented")
}

func (n nullmock) HasSMRR() (bool, error) {
	return false, fmt.Errorf("Not implemented")
}

func (n nullmock) GetSMRRInfo() (SMRR, error) {
	return SMRR{}, fmt.Errorf("Not implemented")
}

func (n nullmock) IA32FeatureControlIsLocked() (bool, error) {
	return false, fmt.Errorf("Not implemented")
}

func (n nullmock) IA32PlatformID() (uint64, error) {
	return 0, fmt.Errorf("Not implemented")
}

func (n nullmock) AllowsVMXInSMX() (bool, error) {
	return false, fmt.Errorf("Not implemented")
}

func (n nullmock) TXTLeavesAreEnabled() (bool, error) {
	return false, fmt.Errorf("Not implemented")
}
func (n nullmock) IA32DebugInterfaceEnabledOrLocked() (bool, bool, bool, error) {
	return false, false, false, fmt.Errorf("Not implemented")
}

func (n nullmock) PCIReadConfigSpace(bus int, device int, devFn int, off int, buf interface{}) error {
	return fmt.Errorf("Not implemented")
}

func (n nullmock) PCIReadConfig16(bus int, device int, devFn int, off int) (uint16, error) {
	return 0, fmt.Errorf("Not implemented")
}

func (n nullmock) PCIReadConfig32(bus int, device int, devFn int, off int) (uint32, error) {
	return 0, fmt.Errorf("Not implemented")
}

func (n nullmock) PCIReadVendorID(bus int, device int, devFn int) (uint16, error) {
	return 0, fmt.Errorf("Not implemented")
}

func (n nullmock) PCIReadDeviceID(bus int, device int, devFn int) (uint16, error) {
	return 0, fmt.Errorf("Not implemented")
}

func (n nullmock) ReadHostBridgeTseg() (uint32, uint32, error) {
	return 0, 0, fmt.Errorf("Not implemented")
}

func (n nullmock) ReadHostBridgeDPR() (DMAProtectedRange, error) {
	return DMAProtectedRange{}, fmt.Errorf("Not implemented")
}

func (n nullmock) ReadPhys(addr int64, data UintN) error {
	return fmt.Errorf("Not implemented")
}

func (n nullmock) ReadPhysBuf(addr int64, buf []byte) error {
	return fmt.Errorf("Not implemented")
}

func (n nullmock) WritePhys(addr int64, data UintN) error {
	return fmt.Errorf("Not implemented")
}

func (n nullmock) NVReadAll(conn io.ReadWriteCloser, index uint32) []byte {
	return []byte{}
}

func GetNullMock() ApiInterfaces {
	return nullmock{}
}
