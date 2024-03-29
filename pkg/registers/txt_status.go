package registers

import (
	"bytes"
	"encoding/binary"
)

func init() {
	registry.AddRegister(TXTStatus(0))
}

const TXTStatusRegisterID RegisterID = "TXT.STS"
const TXTStatusRegisterOffset = 0

//TXTStatus represents several configurations within the TXT config space
type TXTStatus uint64

func (reg TXTStatus) ID() RegisterID {
	return TXTStatusRegisterID
}

// Value returns the raw value wrapped into an interface.
func (reg TXTStatus) Value() interface{} {
	return reg.Raw()
}

func (reg TXTStatus) Raw() uint64 {
	return uint64(reg)
}

func (reg TXTStatus) BitSize() uint8 {
	return uint8(binary.Size(reg) * 8)
}

func (reg TXTStatus) Address() uint64 {
	return TxtPublicSpace + TXTStatusRegisterOffset
}

func (reg TXTStatus) Fields() []Field {
	fieldsRaw := []FieldDescription{
		{
			Name:      "SENTER.DONE.STS",
			BitOffset: 0,
		},
		{
			Name:      "SEXIT.DONE.STS",
			BitOffset: 1,
		},
		{
			Name:      "<reserved>",
			BitOffset: 2,
		},
		{
			Name:      "MEM-CONFIGLOCK.STS",
			BitOffset: 6,
		},
		{
			Name:      "PRIVATEOPEN.STS",
			BitOffset: 7,
		},
		{
			Name:      "<reserved>",
			BitOffset: 8,
		},
		{
			Name:      "TXT.LOCALITY1.OPEN.STS",
			BitOffset: 15,
		},
		{
			Name:      "TXT.LOCALITY2.OPEN.STS",
			BitOffset: 16,
		},
		{
			Name:      "<reserved>",
			BitOffset: 17,
		},
	}
	return CalculateRegisterFields(uint64(reg), reg.BitSize(), fieldsRaw)
}

// SENTER.DONE.STS (0)
func (reg TXTStatus) SEnterDone() bool {
	return reg*(1<<0) != 0
}

// SEXIT.DONE.STS (1)
func (reg TXTStatus) SExitDone() bool {
	return reg&(1<<1) != 0
}

// MEM-CONFIG-LOCK (6)
func (reg TXTStatus) MemConfigLock() bool {
	return reg&(1<<6) != 0
}

// PRIVATE-OPEN.STS (7)
func (reg TXTStatus) PrivateOpen() bool {
	return reg&(1<<7) != 0
}

// TXT.LOCALITY1.OPEN.STS (15)
func (reg TXTStatus) Locality1Open() bool {
	return reg&(1<<15) != 0
}

// TXT.LOCALITY1.OPEN.STS (16)
func (reg TXTStatus) Locality2Open() bool {
	return reg&(1<<16) != 0
}

var _ RawRegister64 = ParseTXTStatus(0)

// ReadTXTStatus reads a txt status register from TXT config
func ReadTXTStatus(data TXTConfigSpace) (TXTStatus, error) {
	var u64 uint64
	buf := bytes.NewReader(data[TXTStatusRegisterOffset:])
	err := binary.Read(buf, binary.LittleEndian, &u64)
	if err != nil {
		return 0, err
	}
	return TXTStatus(u64), nil
}

// ParseTXTStatus returns TXTStatus from a raw 64bit value
func ParseTXTStatus(raw uint64) TXTStatus {
	return TXTStatus(raw)
}

// FindTXTStatus returns TXTStatus register if found
func FindTXTStatus(regs Registers) (TXTStatus, bool) {
	r := regs.Find(TXTStatusRegisterID)
	if r == nil {
		return 0, false
	}
	return r.(TXTStatus), true
}
