package registers

func init() {
	registry.AddRegister(BootGuardPBEC(0))
}

const BootGuardPBECRegisterID = "BOOT_GUARD_PBEC"
const BootGuardPBECRegisterOffset = 0x139

type BootGuardPBEC uint64

func (reg BootGuardPBEC) ID() RegisterID {
	return BootGuardPBECRegisterID
}

func (reg BootGuardPBEC) BitSize() uint8 {
	return 64
}

func (reg BootGuardPBEC) Address() uint64 {
	return BootGuardPBECRegisterOffset
}

func (reg BootGuardPBEC) Fields() []Field {
	fieldsRaw := []FieldDescription{
		{
			Name:      "StopPBET",
			BitOffset: 0,
		},
		{
			Name:      "<reserved>",
			BitOffset: 1,
		},
	}
	return CalculateRegisterFields(reg.Raw(), reg.BitSize(), fieldsRaw)
}

// Value returns the raw value wrapped into an interface.
func (reg BootGuardPBEC) Value() interface{} {
	return reg.Raw()
}

func (reg BootGuardPBEC) Raw() uint64 {
	return uint64(reg)
}

func (reg BootGuardPBEC) StopPBET() bool {
	return reg&0x1 != 0
}

var _ RawRegister64 = ParseBootGuardPBEC(0)

// ReadBootGuardPBEC reads IA32FeatureControl MSR register
func ReadBootGuardPBEC(msrReader MSRReader) (BootGuardPBEC, error) {
	value, err := msrReader.Read(BootGuardPBECRegisterOffset)
	if err != nil {
		return 0, err
	}
	return ParseBootGuardPBEC(value), nil
}

// ParseBootGuardPBEC returns BootGuardPBEC from a raw 64bit value
func ParseBootGuardPBEC(raw uint64) BootGuardPBEC {
	return BootGuardPBEC(raw)
}

// FindBootGuardPBEC returns BootGuardPBEC register if found
func FindBootGuardPBEC(regs Registers) (BootGuardPBEC, bool) {
	r := regs.Find(BootGuardPBECRegisterID)
	if r == nil {
		return 0, false
	}
	return r.(BootGuardPBEC), true
}
