package registers

const IA32SMRRPhysBaseRegisterID = "IA32_SMRR_PHYSBASE"
const IA32SMRRPhysBaseRegisterOffset = 0x1F2

type IA32SMRRPhysBase uint64

func (reg IA32SMRRPhysBase) ID() RegisterID {
	return IA32SMRRPhysBaseRegisterID
}

func (reg IA32SMRRPhysBase) BitSize() uint8 {
	return 64
}

func (reg IA32SMRRPhysBase) Fields() []Field {
	fieldsRaw := []fieldDescription{
		{
			name:      "Type",
			bitOffset: 0,
		},
		{
			name:      "<reserved>",
			bitOffset: 8,
		},
		{
			name:      "PhysBase",
			bitOffset: 12,
		},
		{
			name:      "<reserved>",
			bitOffset: 32,
		},
	}
	return calculateRegisterFields(reg.Raw(), reg.BitSize(), fieldsRaw)
}

func (reg IA32SMRRPhysBase) Raw() uint64 {
	return uint64(reg)
}

func (reg IA32SMRRPhysBase) Type() uint8 {
	return uint8(reg & 0xff)
}

func (reg IA32SMRRPhysBase) PhysBase() uint32 {
	return uint32((reg >> 12) & 0xfffff)
}

var _ RawRegister64 = ParseIA32SMRRPhysBase(0)

// ReadIA32SMRRPhysBase reads IA32SMRRPhysBase MSR register
func ReadIA32SMRRPhysBase(msrReader MSRReader) (IA32SMRRPhysBase, error) {
	value, err := msrReader.Read(IA32SMRRPhysBaseRegisterOffset)
	if err != nil {
		return 0, err
	}
	return ParseIA32SMRRPhysBase(value), nil
}

// ParseIA32SMRRPhysBase returns IA32SMRRPhysBase from a raw 64bit value
func ParseIA32SMRRPhysBase(raw uint64) IA32SMRRPhysBase {
	return IA32SMRRPhysBase(raw)
}

// FindIA32SMRRPhysBase returns IA32SMRRPhysBase register if found
func FindIA32SMRRPhysBase(regs Registers) (IA32SMRRPhysBase, bool) {
	r := regs.Find(IA32SMRRPhysBaseRegisterID)
	if r == nil {
		return 0, false
	}
	return r.(IA32SMRRPhysBase), true
}
