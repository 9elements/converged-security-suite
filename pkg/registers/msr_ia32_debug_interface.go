package registers

func init() {
	registry.AddRegister(IA32DebugInterface(0))
}

const IA32DebugInterfaceRegisterID = "IA32_DEBUG_INTERFACE"
const IA32DebugInterfaceRegisterOffset = 0xC80

type IA32DebugInterface uint64

func (reg IA32DebugInterface) ID() RegisterID {
	return IA32DebugInterfaceRegisterID
}

func (reg IA32DebugInterface) BitSize() uint8 {
	return 64
}

func (reg IA32DebugInterface) Address() uint64 {
	return IA32DebugInterfaceRegisterOffset
}

func (reg IA32DebugInterface) Fields() []Field {
	fieldsRaw := []FieldDescription{
		{
			Name:      "Enable",
			BitOffset: 0,
		},
		{
			Name:      "<reserved>",
			BitOffset: 1,
		},
		{
			Name:      "Lock",
			BitOffset: 30,
		},
		{
			Name:      "DebugOccurred",
			BitOffset: 31,
		},
		{
			Name:      "<reserved>",
			BitOffset: 32,
		},
	}
	return CalculateRegisterFields(reg.Raw(), reg.BitSize(), fieldsRaw)
}

// Value returns the raw value wrapped into an interface.
func (reg IA32DebugInterface) Value() interface{} {
	return reg.Raw()
}

func (reg IA32DebugInterface) Raw() uint64 {
	return uint64(reg)
}

func (reg IA32DebugInterface) Enabled() bool {
	return reg&0x1 != 0
}

func (reg IA32DebugInterface) Locked() bool {
	return (reg>>30)&0x1 != 0
}

func (reg IA32DebugInterface) DebugOccurred() bool {
	return (reg>>31)&0x1 != 0
}

var _ RawRegister64 = ParseIA32PlatformID(0)

// ReadIA32DebugInterface reads IA32DebugInterface MSR register
func ReadIA32DebugInterface(msrReader MSRReader) (IA32DebugInterface, error) {
	value, err := msrReader.Read(IA32DebugInterfaceRegisterOffset)
	if err != nil {
		return 0, err
	}
	return ParseIA32DebugInterface(value), nil
}

// ParseIA32DebugInterface returns IA32DebugInterface from a raw 64bit value
func ParseIA32DebugInterface(raw uint64) IA32DebugInterface {
	return IA32DebugInterface(raw)
}

// FindIA32DebugInterface returns IA32DebugInterface register if found
func FindIA32DebugInterface(regs Registers) (IA32DebugInterface, bool) {
	r := regs.Find(IA32DebugInterfaceRegisterID)
	if r == nil {
		return 0, false
	}
	return r.(IA32DebugInterface), true
}
