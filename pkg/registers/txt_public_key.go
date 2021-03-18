package registers

import (
	"bytes"
	"encoding/binary"
)

const TXTPublicKeyRegisterID RegisterID = "TXT.PUBLIC.KEY"
const TXTPublicKeyRegisterOffset = 0x400

type TXTPublicKey struct {
	publicKey [32]uint8
}

func (reg TXTPublicKey) ID() RegisterID {
	return TXTPublicKeyRegisterID
}

func (reg TXTPublicKey) Raw() []byte {
	return reg.publicKey[:]
}

func (reg TXTPublicKey) BitSize() uint8 {
	return uint8(binary.Size(reg) * 8)
}

func (reg TXTPublicKey) Fields() []Field {
	keyField := Field{
		Name:      "Hash of the public key used for verification of AC modules",
		BitOffset: 0,
		BitSize:   reg.BitSize(),
	}
	b := reg.Raw()
	keyField.Value = b[:]
	return []Field{
		keyField,
	}
}

var _ RawRegister = TXTPublicKey{}

// ReadTXTPublicKey reads a txt public key register from TXT config
func ReadTXTPublicKeyRegister(data TXTConfigSpace) (TXTPublicKey, error) {
	buf := bytes.NewReader(data[TXTPublicKeyRegisterOffset:])
	var register TXTPublicKey
	if err := binary.Read(buf, binary.LittleEndian, &register.publicKey); err != nil {
		return register, err
	}
	return register, nil
}

// ParseTXTPublicKey returns TXTPublicKey from a raw 64bit value
func ParseTXTPublicKey(raw [32]uint8) TXTPublicKey {
	return TXTPublicKey{
		publicKey: raw,
	}
}

// FindTXTPublicKey returns TXTPublicKey register if found
func FindTXTPublicKey(regs Registers) (TXTPublicKey, bool) {
	r := regs.Find(TXTPublicKeyRegisterID)
	if r == nil {
		return TXTPublicKey{}, false
	}
	return r.(TXTPublicKey), true
}
