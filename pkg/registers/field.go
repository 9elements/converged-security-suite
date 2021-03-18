package registers

import "encoding/binary"

// Field is a single field inside of register. It is usually only few bits
// of a register.
type Field struct {
	// Name defines field's name/description
	Name string

	// BitOffset defines field's starting position in the register
	BitOffset uint8

	// BitSize defines how many bits in the register is dedicated to this field.
	BitSize uint8

	// Value is either binary or numeric value (LittleEndian decoded) representation of the field.
	Value []byte
}

type fieldDescription struct {
	name      string
	bitOffset uint8
}

// calculateRegisterFields is a handy helper that calculate final fields representation
func calculateRegisterFields(registerValue uint64, registerSize uint8, fields []fieldDescription) []Field {
	if len(fields) == 0 {
		return nil
	}

	result := make([]Field, 0, len(fields))

	fieldsTotalSize := uint8(0)
	var lastBitOffset uint8
	for i := 1; i < len(fields)+1; i++ {
		field := Field{
			Name:      fields[i-1].name,
			BitOffset: fields[i-1].bitOffset,
		}

		if lastBitOffset > fields[i-1].bitOffset {
			panic("input fields should be sorted by bitOffset")
		}
		lastBitOffset = fields[i-1].bitOffset

		if i == len(fields) {
			field.BitSize = registerSize - field.BitOffset
		} else {
			field.BitSize = fields[i].bitOffset - field.BitOffset
		}
		v := (registerValue >> fieldsTotalSize) & ((1 << field.BitSize) - 1)
		field.Value = NumberToFieldValue(v)
		fieldsTotalSize += field.BitSize

		result = append(result, field)
	}
	return result
}

// NumberToFieldValue packs a given number into bytes array in little endian format
// Used for Field.Value
func NumberToFieldValue(n uint64) []byte {
	result := make([]byte, 8)
	binary.LittleEndian.PutUint64(result, n)
	return result
}

// FieldValueToNumber restores a number from a byte array in little endian format
// Used for Field.Value
func FieldValueToNumber(value []byte) uint64 {
	return binary.LittleEndian.Uint64(value)
}
