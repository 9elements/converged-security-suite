package registers

import "encoding/json"

// RegisterID is a unique id of a register (either TXT or MSR)
type RegisterID string

// Register represents an abstract register
type Register interface {
	ID() RegisterID
	BitSize() uint8
	Fields() []Field
	Address() uint64
}

// RawRegister is a simple accessor to variable length registers
type RawRegister interface {
	Register
	Raw() []byte
}

// RawRegister8 is a simple accessor to 8-bit sized registers
type RawRegister8 interface {
	Register
	Raw() uint8
}

// RawRegister16 is a simple accessor to 16-bit sized registers
type RawRegister16 interface {
	Register
	Raw() uint16
}

// RawRegister32 is a simple accessor to 32-bit sized registers
type RawRegister32 interface {
	Register
	Raw() uint32
}

// RawRegister64 is a simple accessor to 64-bit sized registers
type RawRegister64 interface {
	Register
	Raw() uint64
}

// Registers represents an abstract collection of some registers
type Registers []Register

// Find searches for a register with a given id in collection
// if there is no register with such id, nil is returned
func (regs Registers) Find(id RegisterID) Register {
	for _, reg := range regs {
		if reg.ID() == id {
			return reg
		}
	}
	return nil
}

type registerJSON struct {
	ID    RegisterID `json:"id"`
	Value []byte     `json:"value"`
}

// MarshalJSON converts a collection of registers into a JSON
func (regs Registers) MarshalJSON() ([]byte, error) {
	resultRegisters := make([]registerJSON, 0, len(regs))
	for _, reg := range regs {
		v, err := MarshalValue(reg)
		if err != nil {
			return nil, err
		}
		resultRegisters = append(resultRegisters, registerJSON{
			ID:    reg.ID(),
			Value: v,
		})
	}
	return json.Marshal(resultRegisters)
}

// UnmarshalJSON parses registers from JSON that was previously obtained using MarshalJSON
func (regs *Registers) UnmarshalJSON(b []byte) error {
	var jsonRegisters []registerJSON
	if err := json.Unmarshal(b, &jsonRegisters); err != nil {
		return err
	}

	resultRegisters := make(Registers, 0, len(jsonRegisters))
	for _, jsonReg := range jsonRegisters {
		reg, err := Unmarshal(jsonReg.ID, jsonReg.Value)
		if err != nil {
			return err
		}
		resultRegisters = append(resultRegisters, reg)
	}
	*regs = resultRegisters
	return nil
}
