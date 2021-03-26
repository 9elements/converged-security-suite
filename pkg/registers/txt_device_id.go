package registers

import (
	"bytes"
	"encoding/binary"
)

const TXTDeviceIDRegisterID RegisterID = "TXT.DIDVID"
const TXTDeviceIDRegisterOffset = 0x110

type TXTDeviceID uint64

func (reg TXTDeviceID) ID() RegisterID {
	return TXTDeviceIDRegisterID
}

func (reg TXTDeviceID) Raw() uint64 {
	return uint64(reg)
}

func (reg TXTDeviceID) BitSize() uint8 {
	return uint8(binary.Size(reg) * 8)
}

func (reg TXTDeviceID) Fields() []Field {
	fieldsRaw := []fieldDescription{
		{
			name:      "Vendor ID",
			bitOffset: 0,
		},
		{
			name:      "Device ID",
			bitOffset: 16,
		},
		{
			name:      "Revision ID",
			bitOffset: 32,
		},
		{
			name:      "Extended ID",
			bitOffset: 48,
		},
	}
	return calculateRegisterFields(reg.Raw(), reg.BitSize(), fieldsRaw)
}

func (reg TXTDeviceID) VendorID() uint16 {
	return uint16(reg & 0xffff)
}

func (reg TXTDeviceID) DeviceID() uint16 {
	return uint16((reg >> 16) & 0xffff)
}

func (reg TXTDeviceID) RevisionID() uint16 {
	return uint16((reg >> 32) & 0xffff)
}

func (reg TXTDeviceID) ExtendedID() uint16 {
	return uint16((reg >> 48) & 0xffff)
}

var _ RawRegister64 = ParseTXTDeviceID(0)

// ReadTXTDeviceIDRegister reads a txt error status register from TXT config
func ReadTXTDeviceIDRegister(data TXTConfigSpace) (TXTDeviceID, error) {
	buf := bytes.NewReader(data[TXTDeviceIDRegisterOffset:])
	var u64 uint64
	if err := binary.Read(buf, binary.LittleEndian, &u64); err != nil {
		return 0, err
	}
	return ParseTXTDeviceID(u64), nil
}

// ParseTXTDeviceID returns TXTErrorStatus from a raw 64bit value
func ParseTXTDeviceID(raw uint64) TXTDeviceID {
	return TXTDeviceID(raw)
}

// FindTXTDeviceID returns TXTDeviceID register if found
func FindTXTDeviceID(regs Registers) (TXTDeviceID, bool) {
	r := regs.Find(TXTDeviceIDRegisterID)
	if r == nil {
		return 0, false
	}
	return r.(TXTDeviceID), true
}
