package registers

const IA32SMRRPhysMaskRegisterID = "IA32_SMRR_PHYSMASK"
const IA32SMRRPhysMaskRegisterOffset = 0x1F3

type IA32SMRRPhysMask uint64

func (reg IA32SMRRPhysMask) ID() RegisterID {
	return IA32SMRRPhysMaskRegisterID
}

func (reg IA32SMRRPhysMask) BitSize() uint8 {
	return 64
}

func (reg IA32SMRRPhysMask) Fields() []Field {
	fieldsRaw := []fieldDescription{
		{
			name:      "<reserved>",
			bitOffset: 0,
		},
		{
			name:      "V (Valid)",
			bitOffset: 11,
		},
		{
			name:      "PhysMask",
			bitOffset: 12,
		},
		{
			name:      "<reserved>",
			bitOffset: 32,
		},
	}
	return calculateRegisterFields(reg.Raw(), reg.BitSize(), fieldsRaw)
}

func (reg IA32SMRRPhysMask) Raw() uint64 {
	return uint64(reg)
}

func (reg IA32SMRRPhysMask) Valid() bool {
	return (reg>>11)&0x1 != 0
}

func (reg IA32SMRRPhysMask) PhysMask() uint32 {
	return uint32(reg >> 12 & 0xfffff)
}

var _ RawRegister64 = ParseIA32SMRRPhysMask(0)

// ReadIA32SMRRPhysMask reads IA32SMRRPhysMask MSR register
func ReadIA32SMRRPhysMask(msrReader MSRReader) (IA32SMRRPhysMask, error) {
	value, err := msrReader.Read(IA32SMRRPhysMaskRegisterOffset)
	if err != nil {
		return 0, err
	}
	return ParseIA32SMRRPhysMask(value), nil
}

// ParseIA32SMRRPhysMask returns IA32SMRRPhysMask from a raw 64bit value
func ParseIA32SMRRPhysMask(raw uint64) IA32SMRRPhysMask {
	return IA32SMRRPhysMask(raw)
}

// FindIA32SMRRPhysBase returns IA32SMRRPhysBase register if found
func FindIA32SMRRPhysMask(regs Registers) (IA32SMRRPhysMask, bool) {
	r := regs.Find(IA32SMRRPhysMaskRegisterID)
	if r == nil {
		return 0, false
	}
	return r.(IA32SMRRPhysMask), true
}
