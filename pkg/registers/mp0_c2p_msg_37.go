package registers

const MP0C2PMSG37RegisterID RegisterID = "MP0_C2P_MSG_37"

type MP0C2PMsg37 uint32

// ID returns the MP0_C2P_MSG_37 register ID
func (r MP0C2PMsg37) ID() RegisterID {
	return MP0C2PMSG37RegisterID
}

// BitSize returns the size of MP0_C2P_MSG_37 register in bits
func (r MP0C2PMsg37) BitSize() uint8 {
	return 32
}

// Fields returns the internal fields of MP0_C2P_MSG_37 register
func (r MP0C2PMsg37) Fields() []Field {
	fieldsRaw := []FieldDescription{
		{
			Name:      "<reserved>",
			BitOffset: 0,
		},
		{
			Name:      "PLATFORM_SECURE_BOOT_EN: Fuse bit that controls platform secure boot enable enforced mode.",
			BitOffset: 24,
		},
		{
			Name:      "<reserved>",
			BitOffset: 25,
		},
	}
	return CalculateRegisterFields(uint64(r.Raw()), r.BitSize(), fieldsRaw)
}

// Raw returns the raw value of of MP0_C2P_MSG_37 register
func (r MP0C2PMsg37) Raw() uint32 {
	return uint32(r)
}

// Address returns 0 as MP0_C2P_MSG_37 is not bound to memory
func (r MP0C2PMsg37) Address() uint64 {
	return 0
}

// IsPlatformSecureBootEnabled specifies if PSB is enabled and enforced
func (r MP0C2PMsg37) IsPlatformSecureBootEnabled() bool {
	return (r>>24)&0x1 == 1
}

var _ RawRegister32 = ParseMP0C2PMsg37Register(0)

// ParseMP0C2PMsg37Register returns MP0C2PMsg37Register from a raw 32bit value
func ParseMP0C2PMsg37Register(raw uint32) MP0C2PMsg37 {
	return MP0C2PMsg37(raw)
}

// FindMP0C2PMsg37 returns MP0C2PMsg37 register if found
func FindMP0C2PMsg37(regs Registers) (MP0C2PMsg37, bool) {
	r := regs.Find(MP0C2PMSG37RegisterID)
	if r == nil {
		return 0, false
	}
	return r.(MP0C2PMsg37), true
}
