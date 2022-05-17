package registers

func init() {
	registry.AddRegister(MP0C2PMsg38(0))
}

const MP0C2PMSG38RegisterID RegisterID = "MP0_C2P_MSG_38"

type MP0C2PMsg38 uint32

// ID returns the MP0_C2P_MSG_38 register ID
func (r MP0C2PMsg38) ID() RegisterID {
	return MP0C2PMSG38RegisterID
}

// BitSize returns the size of MP0_C2P_MSG_38 register in bits
func (r MP0C2PMsg38) BitSize() uint8 {
	return 32
}

// Fields returns the internal fields of MP0_C2P_MSG_38 register
func (r MP0C2PMsg38) Fields() []Field {
	fieldsRaw := []FieldDescription{
		{
			Name:      "<reserved>",
			BitOffset: 0,
		},
	}
	return CalculateRegisterFields(uint64(r.Raw()), r.BitSize(), fieldsRaw)
}

// Value returns the raw value wrapped into an interface.
func (r MP0C2PMsg38) Value() interface{} {
	return r.Raw()
}

// Raw returns the raw value of of MP0_C2P_MSG_37 register
func (r MP0C2PMsg38) Raw() uint32 {
	return uint32(r)
}

// Address returns 0 as MP0_C2P_MSG_37 is not bound to memory
func (r MP0C2PMsg38) Address() uint64 {
	return 0
}

var _ RawRegister32 = ParseMP0C2PMsg38Register(0)

// ParseMP0C2PMsg38Register returns MP0C2PMsg38 register from a raw 32bit value
func ParseMP0C2PMsg38Register(raw uint32) MP0C2PMsg38 {
	return MP0C2PMsg38(raw)
}

// FindMP0C2PMsg38 returns MP0C2PMsg38 register if found
func FindMP0C2PMsg38(regs Registers) (MP0C2PMsg38, bool) {
	r := regs.Find(MP0C2PMSG38RegisterID)
	if r == nil {
		return 0, false
	}
	return r.(MP0C2PMsg38), true
}
