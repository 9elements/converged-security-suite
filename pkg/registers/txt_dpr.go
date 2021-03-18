package registers

import (
	"bytes"
	"encoding/binary"
)

const TXTDMAProtectedRangeRegisterID RegisterID = "TXT.DPR"
const TXTDMAProtectedRangeRegisterOffset = 0x330

//DMAProtectedRange encodes the DPR register
type DMAProtectedRange struct {
	Lock bool
	// Reserved 1-3
	Size uint8
	// Reserved 12-19
	Top uint16
}

type TXTDMAProtectedRange uint32

func (reg TXTDMAProtectedRange) ID() RegisterID {
	return TXTDMAProtectedRangeRegisterID
}

func (reg TXTDMAProtectedRange) Raw() uint32 {
	return uint32(reg)
}

func (reg TXTDMAProtectedRange) BitSize() uint8 {
	return 32
}

func (reg TXTDMAProtectedRange) Fields() []Field {
	fieldsRaw := []fieldDescription{
		{
			name:      "Lock",
			bitOffset: 0,
		},
		{
			name:      "<reserved>",
			bitOffset: 1,
		},
		{
			name:      "Size of memory, in MB, that will be protected from DMA access",
			bitOffset: 4,
		},
		{
			name:      "<reserved>",
			bitOffset: 12,
		},
		{
			name:      "Top address + 1 of DPR. This is the base of TSEG",
			bitOffset: 20,
		},
	}
	return calculateRegisterFields(uint64(reg), reg.BitSize(), fieldsRaw)
}

func (reg TXTDMAProtectedRange) DMAProtectedRange() DMAProtectedRange {
	u32 := uint32(reg)
	return DMAProtectedRange{
		Lock: u32&1 != 0,
		Size: uint8((u32 >> 4) & 0xff),    // 11:4
		Top:  uint16((u32 >> 20) & 0xfff), // 31:20
	}
}

var _ RawRegister32 = ParseTXTDMAProtectedRangeRegister(0)

// ReadTXTDMAProtectedRangeRegister reads the raw DMA protected range register from TXT config
func ReadTXTDMAProtectedRangeRegister(data TXTConfigSpace) (TXTDMAProtectedRange, error) {
	var u32 uint32
	buf := bytes.NewReader(data[TXTDMAProtectedRangeRegisterOffset:])
	err := binary.Read(buf, binary.LittleEndian, &u32)
	if err != nil {
		return 0, err
	}
	return TXTDMAProtectedRange(u32), nil
}

// ParseTXTDMAProtectedRangeRegister returns TXTDMAProtectedRange from a raw 64bit value
func ParseTXTDMAProtectedRangeRegister(raw uint32) TXTDMAProtectedRange {
	return TXTDMAProtectedRange(raw)
}

// FindTXTDMAProtectedRange returns TXTDMAProtectedRange register if found
func FindTXTDMAProtectedRange(regs Registers) (TXTDMAProtectedRange, bool) {
	r := regs.Find(TXTDMAProtectedRangeRegisterID)
	if r == nil {
		return 0, false
	}
	return r.(TXTDMAProtectedRange), true
}
