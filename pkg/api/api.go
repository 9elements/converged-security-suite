package api

import "io"

type ApiInterfaces interface {
	CPUBlacklistTXTSupport() bool
	CPUWhitelistTXTSupport() bool

	VersionString() string
	HasSMX() bool
	HasVMX() bool
	HasMTRR() bool
	ProcessorBrandName() string
	CPUSignature() uint32
	CPULogCount() uint32

	IsReservedInE810(start uint64, end uint64) (bool, error)

	LookupIOAddress(addr uint64, regs VTdRegisters) ([]uint64, error)
	AddressRangesIsDMAProtected(first, end uint64) (bool, error)

	HasSMRR() (bool, error)
	GetSMRRInfo() (SMRR, error)
	IA32FeatureControlIsLocked() (bool, error)
	IA32PlatformID() (uint64, error)
	AllowsVMXInSMX() (bool, error)
	TXTLeavesAreEnabled() (bool, error)
	IA32DebugInterfaceEnabledOrLocked() (bool, bool, bool, error)

	PCIReadConfigSpace(bus int, device int, devFn int, off int, buf interface{}) error
	PCIReadConfig16(bus int, device int, devFn int, off int) (uint16, error)
	PCIReadConfig32(bus int, device int, devFn int, off int) (uint32, error)
	PCIReadVendorID(bus int, device int, devFn int) (uint16, error)
	PCIReadDeviceID(bus int, device int, devFn int) (uint16, error)
	ReadHostBridgeTseg() (uint32, uint32, error)
	ReadHostBridgeDPR() (DMAProtectedRange, error)

	ReadPhys(addr int64, data UintN) error
	ReadPhysBuf(addr int64, buf []byte) error
	WritePhys(addr int64, data UintN) error

	NVReadAll(conn io.ReadWriteCloser, index uint32) []byte
}

//TxtApi The context object for TXT Api
type TxtApi struct{}

//GetApi Returns an initialized TxtApi object
func GetApi() ApiInterfaces {
	return TxtApi{}
}
