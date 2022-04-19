package registers

import (
	"encoding/json"
	"fmt"
	"sort"

	"gopkg.in/yaml.v3"
)

// RegisterID is a unique id of a register (either TXT or MSR)
type RegisterID string

// Register represents an abstract register
type Register interface {
	ID() RegisterID
	BitSize() uint8
	Fields() []Field
	Address() uint64
	Value() interface{}
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

// New constructs a register, given its ID and raw value. It
// will return an error if the value is of wrong underlying type.
func New(regID RegisterID, value interface{}) (Register, error) {
	return registry.New(regID, value)
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

type registerForSerializationOBSOLETE struct {
	ID    RegisterID `json:"id"`
	Value []byte     `json:"value"`
}

type registersForSerializationOBSOLETE []registerForSerializationOBSOLETE

func (regs registersForSerializationOBSOLETE) ParseRegisters() (Registers, error) {
	resultRegisters := make(Registers, 0, len(regs))
	for idx, regS := range regs {
		v, err := ValueFromBytes(regS.ID, regS.Value)
		if err != nil {
			return nil, fmt.Errorf("unable to un-base64 value %d:'%s': %w", idx, regS.Value, err)
		}
		reg, err := New(regS.ID, v)
		if err != nil {
			return nil, err
		}
		resultRegisters = append(resultRegisters, reg)
	}
	return resultRegisters, nil
}

func (regs Registers) forSerializationOBSOLETE() (registersForSerializationOBSOLETE, error) {
	resultRegisters := make(registersForSerializationOBSOLETE, 0, len(regs))
	for _, reg := range regs {
		b, err := ValueBytes(reg)
		if err != nil {
			return nil, fmt.Errorf("unable to serialize the value of register %T:%v", reg, reg)
		}
		resultRegisters = append(resultRegisters, registerForSerializationOBSOLETE{
			ID:    reg.ID(),
			Value: b,
		})
	}
	return resultRegisters, nil
}

// MarshalJSON converts a collection of registers into a JSON
// TODO: remove this, obsolete format
// OBSOLETE
func (regs Registers) MarshalJSON() ([]byte, error) {
	v, err := regs.forSerializationOBSOLETE()
	if err != nil {
		return nil, err
	}
	return json.Marshal(v)
}

// UnmarshalJSON parses registers from JSON that was previously obtained using MarshalJSON
// TODO: remove this, obsolete format
// OBSOLETE
func (regs *Registers) UnmarshalJSON(b []byte) error {
	var jsonRegisters registersForSerializationOBSOLETE
	if err := json.Unmarshal(b, &jsonRegisters); err != nil {
		return fmt.Errorf("unable to un-JSON-ize registers: %w", err)
	}
	resultRegisters, err := jsonRegisters.ParseRegisters()
	if err != nil {
		return fmt.Errorf("unable to convert registers: %w", err)
	}
	*regs = resultRegisters
	return nil
}

type registersForSerialization map[RegisterID]interface{}

func (m registersForSerialization) Registers() (Registers, error) {
	resultRegisters := make(Registers, 0, len(m))
	for regID, serializedValue := range m {
		v, err := valueUnpack(regID, serializedValue)
		if err != nil {
			return nil, fmt.Errorf("unable to unpack value '%s': %w", serializedValue, err)
		}
		reg, err := New(regID, v)
		if err != nil {
			return nil, err
		}
		resultRegisters = append(resultRegisters, reg)
	}
	resultRegisters.Sort()
	return resultRegisters, nil
}

// Sort sorts registers in some stable manner
func (regs Registers) Sort() {
	sort.Slice(regs, func(i, j int) bool {
		a0 := regs[i].Address()
		a1 := regs[j].Address()
		if a0 != a1 {
			return a0 < a1
		}
		return regs[i].ID() < regs[j].ID()
	})
}

func (regs Registers) forSerialization() (registersForSerialization, error) {
	m := make(registersForSerialization, len(regs))
	for _, reg := range regs {
		m[reg.ID()] = valueToHex(reg.Value())
	}
	return m, nil
}

// MarshalYAML converts a collection of registers into an YAML
func (regs Registers) MarshalYAML() (interface{}, error) {
	v, err := regs.forSerialization()
	if err != nil {
		return nil, fmt.Errorf("unable to prepare a serializable data structure: %w", err)
	}

	n := &yaml.Node{}
	if err := n.Encode(v); err != nil {
		return nil, fmt.Errorf("unable to encode to YAML: %w", err)
	}
	for _, regYaml := range n.Content {
		regYaml.Style = yaml.TaggedStyle
		regYaml.Tag = ""
	}
	return n, nil
}

// UnmarshalYAML parses registers from YAML that was previously obtained using MarshalYAML
func (regs *Registers) UnmarshalYAML(value *yaml.Node) error {
	var regsYaml registersForSerialization
	if err := value.Decode(&regsYaml); err != nil {
		return fmt.Errorf("unable to un-YAML-ize registers: %w", err)
	}
	result, err := regsYaml.Registers()
	if err != nil {
		return fmt.Errorf("unable to parse registers data: %w", err)
	}
	*regs = result
	return nil
}
