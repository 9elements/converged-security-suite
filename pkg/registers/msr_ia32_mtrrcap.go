package registers

func init() {
	registry.AddRegister(IA32MTRRCAP(0))
}

const IA32MTRRCAPRegisterID = "IA32_MTRRCAP"
const IA32MTRRCAPRegisterOffset = 0xfe

type IA32MTRRCAP uint64

func (reg IA32MTRRCAP) ID() RegisterID {
	return IA32MTRRCAPRegisterID
}

func (reg IA32MTRRCAP) BitSize() uint8 {
	return 64
}

func (reg IA32MTRRCAP) Address() uint64 {
	return IA32MTRRCAPRegisterOffset
}

func (reg IA32MTRRCAP) Fields() []Field {
	fieldsRaw := []FieldDescription{
		{
			Name:      "VCNT (Number of variable range registers)",
			BitOffset: 0,
		},
		{
			Name:      "FIX (Fixed range registers supported)",
			BitOffset: 8,
		},
		{
			Name:      "<reserved>",
			BitOffset: 9,
		},
		{
			Name:      "WC (Write-combining memory type supported)",
			BitOffset: 10,
		},
		{
			Name:      "SMRR interface supported",
			BitOffset: 11,
		},
		{
			Name:      "<reserved>",
			BitOffset: 12,
		},
	}
	return CalculateRegisterFields(reg.Raw(), reg.BitSize(), fieldsRaw)
}

func (reg IA32MTRRCAP) VariableRangeRegistersCount() uint8 {
	return uint8(reg & 0xFF)
}

func (reg IA32MTRRCAP) FixedRangedRegisteredSupported() bool {
	return (reg>>8)&0x1 != 0
}

func (reg IA32MTRRCAP) WriteCombiningMemoryTypeSupported() bool {
	return (reg>>10)&0x1 != 0
}

func (reg IA32MTRRCAP) SMRRInterfaceSupported() bool {
	return (reg>>11)&0x1 != 0
}

// Value returns the raw value wrapped into an interface.
func (reg IA32MTRRCAP) Value() interface{} {
	return reg.Raw()
}

func (reg IA32MTRRCAP) Raw() uint64 {
	return uint64(reg)
}

var _ RawRegister64 = ParseIA32MTRRCAP(0)

// ReadIA32MTRRCAP reads IA32MTRRCAP MSR register
func ReadIA32MTRRCAP(msrReader MSRReader) (IA32MTRRCAP, error) {
	value, err := msrReader.Read(IA32MTRRCAPRegisterOffset)
	if err != nil {
		return 0, err
	}
	return ParseIA32MTRRCAP(value), nil
}

// ParseIA32MTRRCAP returns IA32MTRRCAP from a raw 64bit value
func ParseIA32MTRRCAP(raw uint64) IA32MTRRCAP {
	return IA32MTRRCAP(raw)
}

// FindIA32MTRRCAP returns IA32MTRRCAP register if found
func FindIA32MTRRCAP(regs Registers) (IA32MTRRCAP, bool) {
	r := regs.Find(IA32MTRRCAPRegisterID)
	if r == nil {
		return 0, false
	}
	return r.(IA32MTRRCAP), true
}
