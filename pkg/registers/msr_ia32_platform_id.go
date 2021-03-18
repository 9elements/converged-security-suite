package registers

const IA32PlatformIDRegisterID = "IA32_PLATFORM_ID"
const IA32PlatformIDRegisterOffset = 0x17

type IA32PlatformID uint64

func (reg IA32PlatformID) ID() RegisterID {
	return IA32PlatformIDRegisterID
}

func (reg IA32PlatformID) BitSize() uint8 {
	return 64
}

func (reg IA32PlatformID) Fields() []Field {
	fieldsRaw := []fieldDescription{
		{
			name:      "<reserved>",
			bitOffset: 0,
		},
		{
			name:      "Processor Flag",
			bitOffset: 50,
		},
		{
			name:      "<reserved>",
			bitOffset: 53,
		},
	}
	return calculateRegisterFields(reg.Raw(), reg.BitSize(), fieldsRaw)
}

func (reg IA32PlatformID) Raw() uint64 {
	return uint64(reg)
}

func (reg IA32PlatformID) ProcessorFlag() uint8 {
	return uint8((reg >> 50) & 0x7)
}

var _ RawRegister64 = ParseIA32PlatformID(0)

// ReadIA32PlatformID reads IA32PlatformID MSR register
func ReadIA32PlatformID(msrReader MSRReader) (IA32PlatformID, error) {
	value, err := msrReader.Read(IA32PlatformIDRegisterOffset)
	if err != nil {
		return 0, err
	}
	return ParseIA32PlatformID(value), nil
}

// ParseIA32PlatformID returns IA32PlatformID from a raw 64bit value
func ParseIA32PlatformID(raw uint64) IA32PlatformID {
	return IA32PlatformID(raw)
}

// FindIA32PlatformID returns IA32PlatformID register if found
func FindIA32PlatformID(regs Registers) (IA32PlatformID, bool) {
	r := regs.Find(IA32PlatformIDRegisterID)
	if r == nil {
		return 0, false
	}
	return r.(IA32PlatformID), true
}
