package registers

import (
	"fmt"

	pkgbytes "github.com/9elements/converged-security-suite/v2/pkg/bytes"
	"github.com/9elements/converged-security-suite/v2/pkg/errors"
)

const (
	// TxtTPMDecode for external use
	TxtTPMDecode = 0xFED40000
	// TxtTPMDecodeSize is the size of the TCG defined TIS MMIO space
	TxtTPMDecodeSize = 0x5000
	// TxtPublicSpace for external test
	TxtPublicSpace = 0xFED30000
	// TxtPublicSpaceSize exports the size of TXTPublicSpace in memory map
	TxtPublicSpaceSize = 0x10000
	// TxtPrivateSpace for external test
	TxtPrivateSpace = 0xFED20000
	// TxtPrivateSpaceSize for external test
	TxtPrivateSpaceSize = 0x10000
)

//TXTConfigSpace holds the TXT config space
type TXTConfigSpace []byte

//PhysicalMemoryReader accesses device physical memory
type PhysicalMemoryReader interface {
	ReadPhysBuf(addr int64, buf []byte) error
}

// FetchTXTConfigSpaceRaw returns a raw copy of the TXT config space
//
// Warning, this function may trigger undocumented registers which affects
// other registers or anything else.
func FetchTXTConfigSpaceRaw(mem PhysicalMemoryReader) (TXTConfigSpace, error) {
	data := make([]byte, TxtPublicSpaceSize)
	if err := mem.ReadPhysBuf(TxtPublicSpace, data); err != nil {
		return nil, err
	}
	return data, nil
}

// FetchTXTConfigSpace is a deprecated alias for FetchTXTConfigSpaceRaw.
// DEPRECATED: The function was renamed to FetchTXTConfigSpaceRaw.
func FetchTXTConfigSpace(mem PhysicalMemoryReader) (TXTConfigSpace, error) {
	return FetchTXTConfigSpaceRaw(mem)
}

var (
	physMemDenyList = pkgbytes.Ranges{
		{
			// This is an undocumented register which triggers ACM_POLICY_STATUS
			// corruption.
			Offset: 0xFED30370,
			Length: 8,
		},
	}
)

// FetchTXTConfigSpaceSafe returns a filtered raw copy of the TXT config space,
// it excludes registers, which is not supposed to be read (in contrast
// to FetchTXTConfigSpaceSafe).
func FetchTXTConfigSpaceSafe(mem PhysicalMemoryReader) (TXTConfigSpace, error) {
	data := make([]byte, TxtPublicSpaceSize)

	byteRanges := pkgbytes.Range{
		Offset: TxtPublicSpace,
		Length: TxtPublicSpaceSize,
	}.Exclude(physMemDenyList...)

	for _, byteRange := range byteRanges {
		startIdx := byteRange.Offset - TxtPublicSpace
		endIdx := byteRange.Offset - TxtPublicSpace + byteRange.Length
		if err := mem.ReadPhysBuf(int64(byteRange.Offset), data[startIdx:endIdx]); err != nil {
			return nil, err
		}
	}

	return data, nil
}

type supportedTXTRegister struct {
	id    RegisterID
	fetch func(data TXTConfigSpace) (Register, error)
}

var supportedTXTRegistersIDs = []supportedTXTRegister{
	{
		id: AcmPolicyStatusRegisterID,
		fetch: func(data TXTConfigSpace) (Register, error) {
			return ReadACMPolicyStatusRegister(data)
		},
	},
	{
		id: ACMStatusRegisterID,
		fetch: func(data TXTConfigSpace) (Register, error) {
			return ReadACMStatusRegister(data)
		},
	},
	{
		id: TXTDMAProtectedRangeRegisterID,
		fetch: func(data TXTConfigSpace) (Register, error) {
			return ReadTXTDMAProtectedRangeRegister(data)
		},
	},
	{
		id: TXTErrorCodeRegisterID,
		fetch: func(data TXTConfigSpace) (Register, error) {
			return ReadTxtErrorCode(data)
		},
	},
	{
		id: TXTPublicKeyRegisterID,
		fetch: func(data TXTConfigSpace) (Register, error) {
			return ReadTXTPublicKeyRegister(data)
		},
	},
	{
		id: TXTStatusRegisterID,
		fetch: func(data TXTConfigSpace) (Register, error) {
			return ReadTXTStatus(data)
		},
	},
	{
		id: TXTErrorStatusRegisterID,
		fetch: func(data TXTConfigSpace) (Register, error) {
			return ReadTXTErrorStatusRegister(data)
		},
	},
	{
		id: TXTBootStatusRegisterID,
		fetch: func(data TXTConfigSpace) (Register, error) {
			return ReadTXTBootStatusRegister(data)
		},
	},
	{
		id: TXTVerFSBIfRegisterID,
		fetch: func(data TXTConfigSpace) (Register, error) {
			return ReadTXTVerFSBIF(data)
		},
	},
	{
		id: TXTVerEMIfRegisterID,
		fetch: func(data TXTConfigSpace) (Register, error) {
			return ReadTXTVerEMIF(data)
		},
	},
	{
		id: TXTDeviceIDRegisterID,
		fetch: func(data TXTConfigSpace) (Register, error) {
			return ReadTXTDeviceIDRegister(data)
		},
	},
	{
		id: TXTSINITBaseRegisterID,
		fetch: func(data TXTConfigSpace) (Register, error) {
			return ReadTXTSInitBase(data)
		},
	},
	{
		id: TXTSINITSizeRegisterID,
		fetch: func(data TXTConfigSpace) (Register, error) {
			return ReadTXTSInitSize(data)
		},
	},
	{
		id: TXTMLEJoinRegisterID,
		fetch: func(data TXTConfigSpace) (Register, error) {
			return ReadTXTMLEJoin(data)
		},
	},
	{
		id: TXTHeapBaseRegisterID,
		fetch: func(data TXTConfigSpace) (Register, error) {
			return ReadTXTHeapBase(data)
		},
	},
	{
		id: TXTHeapSizeRegisterID,
		fetch: func(data TXTConfigSpace) (Register, error) {
			return ReadTXTHeapSize(data)
		},
	},
}

// ReadTXTRegisters fetches all supported TXT registers
func ReadTXTRegisters(data TXTConfigSpace) (Registers, error) {
	var result Registers
	var mErr errors.MultiError

	for _, registerInfo := range supportedTXTRegistersIDs {
		reg, err := registerInfo.fetch(data)
		if err != nil {
			mErr.Add(fmt.Errorf("failed to fetch MSR register %s, err: %v", registerInfo.id, err))
			continue
		}
		result = append(result, reg)
	}

	if mErr.Count() > 0 {
		return result, mErr
	}
	return result, nil
}
