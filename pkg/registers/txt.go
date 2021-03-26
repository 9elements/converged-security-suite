package registers

import (
	"bytes"
	"encoding/binary"
	"fmt"
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

//FetchTXTConfigSpace returns a raw copy of the TXT config space
func FetchTXTConfigSpace(txtAPI PhysicalMemoryReader) (TXTConfigSpace, error) {
	data := make([]byte, TxtPublicSpaceSize)
	if err := txtAPI.ReadPhysBuf(TxtPublicSpace, data); err != nil {
		return nil, err
	}
	return data, nil
}

const TXTVerFSBIfRegisterID RegisterID = "TXT.VER.FSBIF"
const TXTVerFSBIfRegisterOffset = 0x100

var ReadTXTVerFSBIfRegister = createSimpleRegister32Reader(TXTVerFSBIfRegisterID, TXTVerFSBIfRegisterOffset)

// FindTXTVerFSBIf returns TXTSInitSize register if found
func FindTXTVerFSBIf(regs Registers) (RawRegister32, bool) {
	r := regs.Find(TXTVerFSBIfRegisterID)
	if r == nil {
		return nil, false
	}
	return r.(RawRegister32), true
}

const TXTVerEMIfRegisterID RegisterID = "TXT.VER.EMIF"
const TXTVerEMIfRegisterOffset = 0x200

var ReadTXTVerEMIfRegister = createSimpleRegister32Reader(TXTVerEMIfRegisterID, TXTVerEMIfRegisterOffset)

// FindTXTVerEMIf returns TXTSInitSize register if found
func FindTXTVerEMIf(regs Registers) (RawRegister32, bool) {
	r := regs.Find(TXTVerEMIfRegisterID)
	if r == nil {
		return nil, false
	}
	return r.(RawRegister32), true
}

const TXTSINITBaseRegisterID RegisterID = "TXT.SINIT.BASE"
const TXTSINITBaseRegisterOffset = 0x270

var ReadTXTSINITBaseRegister = createSimpleRegister32Reader(TXTSINITBaseRegisterID, TXTSINITBaseRegisterOffset)

// FindTXTSInitBase returns TXTSInitBase register if found
func FindTXTSInitBase(regs Registers) (RawRegister32, bool) {
	r := regs.Find(TXTSINITBaseRegisterID)
	if r == nil {
		return nil, false
	}
	return r.(RawRegister32), true
}

const TXTSINITSizeRegisterID RegisterID = "TXT.SINIT.SIZE"
const TXTSINITSizeRegisterOffset = 0x278

var ReadTXTSINITSizeRegister = createSimpleRegister32Reader(TXTSINITSizeRegisterID, TXTSINITSizeRegisterOffset)

// FindTXTSInitSize returns TXTSInitSize register if found
func FindTXTSInitSize(regs Registers) (RawRegister32, bool) {
	r := regs.Find(TXTSINITSizeRegisterID)
	if r == nil {
		return nil, false
	}
	return r.(RawRegister32), true
}

const TXTMLEJoinRegisterID RegisterID = "TXT.MLE.JOIN"
const TXTMLEJoinRegisterOffset = 0x290

var ReadTXTMLEJoinRegister = createSimpleRegister32Reader(TXTMLEJoinRegisterID, TXTMLEJoinRegisterOffset)

// FindTXTMLEJoin returns TXTSInitSize register if found
func FindTXTMLEJoin(regs Registers) (RawRegister32, bool) {
	r := regs.Find(TXTMLEJoinRegisterID)
	if r == nil {
		return nil, false
	}
	return r.(RawRegister32), true
}

const TXTHeapBaseRegisterID RegisterID = "TXT.HEAP.BASE"
const TXTHeapBaseRegisterOffset = 0x300

var ReadTXTHeapBaseRegister = createSimpleRegister32Reader(TXTHeapBaseRegisterID, TXTHeapBaseRegisterOffset)

// FindTXTHeapBase returns TXTHeapBase register if found
func FindTXTHeapBase(regs Registers) (RawRegister32, bool) {
	r := regs.Find(TXTHeapBaseRegisterID)
	if r == nil {
		return nil, false
	}
	return r.(RawRegister32), true
}

const TXTHeapSizeRegisterID RegisterID = "TXT.HEAP.SIZE"
const TXTHeapSizeRegisterOffset = 0x308

// FindTXTHeapSize returns TXTHeapSize register if found
func FindTXTHeapSize(regs Registers) (RawRegister32, bool) {
	r := regs.Find(TXTHeapSizeRegisterID)
	if r == nil {
		return nil, false
	}
	return r.(RawRegister32), true
}

var ReadTXTHeapSizeRegister = createSimpleRegister32Reader(TXTHeapSizeRegisterID, TXTHeapSizeRegisterOffset)

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
			return ReadTXTVerFSBIfRegister(data)
		},
	},
	{
		id: TXTVerEMIfRegisterID,
		fetch: func(data TXTConfigSpace) (Register, error) {
			return ReadTXTVerEMIfRegister(data)
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
			return ReadTXTSINITBaseRegister(data)
		},
	},
	{
		id: TXTSINITSizeRegisterID,
		fetch: func(data TXTConfigSpace) (Register, error) {
			return ReadTXTSINITSizeRegister(data)
		},
	},
	{
		id: TXTMLEJoinRegisterID,
		fetch: func(data TXTConfigSpace) (Register, error) {
			return ReadTXTMLEJoinRegister(data)
		},
	},
	{
		id: TXTHeapBaseRegisterID,
		fetch: func(data TXTConfigSpace) (Register, error) {
			return ReadTXTHeapBaseRegister(data)
		},
	},
	{
		id: TXTHeapSizeRegisterID,
		fetch: func(data TXTConfigSpace) (Register, error) {
			return ReadTXTHeapSizeRegister(data)
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

func createSimpleRegister32Reader(registerID RegisterID, offset uint64) func(data TXTConfigSpace) (RawRegister32, error) {
	return func(data TXTConfigSpace) (RawRegister32, error) {
		buf := bytes.NewReader(data[offset:])
		var ui32 uint32
		if err := binary.Read(buf, binary.LittleEndian, &ui32); err != nil {
			return nil, err
		}
		return &simpleRegister32{
			id:    registerID,
			Value: ui32,
		}, nil
	}
}
