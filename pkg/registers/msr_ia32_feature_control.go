package registers

func init() {
	registry.AddRegister(IA32FeatureControl(0))
}

const IA32FeatureControlRegisterID = "IA32_FEATURE_CONTROL"
const IA32FeatureControlRegisterOffset = 0x3A

type IA32FeatureControl uint64

func (reg IA32FeatureControl) ID() RegisterID {
	return IA32FeatureControlRegisterID
}

func (reg IA32FeatureControl) BitSize() uint8 {
	return 64
}

func (reg IA32FeatureControl) Address() uint64 {
	return IA32FeatureControlRegisterOffset
}

func (reg IA32FeatureControl) Fields() []Field {
	fieldsRaw := []FieldDescription{
		{
			Name:      "Lock (0 = unlocked, 1 = locked)",
			BitOffset: 0,
		},
		{
			Name:      "Enables VMXON in SMX operation",
			BitOffset: 1,
		},
		{
			Name:      "Enables VMXON outside of SMX operation",
			BitOffset: 2,
		},
		{
			Name:      "<reserved>",
			BitOffset: 3,
		},
		{
			Name:      "SENTER Enables",
			BitOffset: 8,
		},
		{
			Name:      "SENTER Global Enable",
			BitOffset: 15,
		},
		{
			Name:      "<reserved>",
			BitOffset: 16,
		},
	}
	return CalculateRegisterFields(reg.Raw(), reg.BitSize(), fieldsRaw)
}

// Value returns the raw value wrapped into an interface.
func (reg IA32FeatureControl) Value() interface{} {
	return reg.Raw()
}

func (reg IA32FeatureControl) Raw() uint64 {
	return uint64(reg)
}

func (reg IA32FeatureControl) Locked() bool {
	return reg&0x1 != 0
}

func (reg IA32FeatureControl) VMXInSMXEnabled() bool {
	return (reg>>1)&0x1 != 0
}

func (reg IA32FeatureControl) VMXOutsideSMXEnabled() bool {
	return (reg>>2)&0x1 != 0
}

func (reg IA32FeatureControl) SENTEREnables() uint8 {
	return uint8((reg >> 8) & 127)
}

func (reg IA32FeatureControl) SENTERGlobalEnable() bool {
	return (reg>>15)&0x1 != 0
}

var _ RawRegister64 = ParseIA32FeatureControl(0)

// ReadIA32FeatureControl reads IA32FeatureControl MSR register
func ReadIA32FeatureControl(msrReader MSRReader) (IA32FeatureControl, error) {
	value, err := msrReader.Read(IA32FeatureControlRegisterOffset)
	if err != nil {
		return 0, err
	}
	return ParseIA32FeatureControl(value), nil
}

// ParseIA32FeatureControl returns IA32FeatureControl from a raw 64bit value
func ParseIA32FeatureControl(raw uint64) IA32FeatureControl {
	return IA32FeatureControl(raw)
}

// FindIA32FeatureControl returns IA32FeatureControl register if found
func FindIA32FeatureControl(regs Registers) (IA32FeatureControl, bool) {
	r := regs.Find(IA32FeatureControlRegisterID)
	if r == nil {
		return 0, false
	}
	return r.(IA32FeatureControl), true
}
