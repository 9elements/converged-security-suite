package registers

func init() {
	registry.AddRegister(BTGSACMInfo(0))
}

const BTGSACMInfoRegisterID = "BTG_SACM_INFO"
const BTGSACMInfoRegisterOffset = 0x13A

type BTGSACMInfo uint64

func (reg BTGSACMInfo) ID() RegisterID {
	return BTGSACMInfoRegisterID
}

func (reg BTGSACMInfo) BitSize() uint8 {
	return 64
}

func (reg BTGSACMInfo) Address() uint64 {
	return BTGSACMInfoRegisterOffset
}

func (reg BTGSACMInfo) Fields() []Field {
	fieldsRaw := []FieldDescription{
		{
			Name:      "NEMEnabled",
			BitOffset: 0,
		},
		{
			Name:      "TPMType",
			BitOffset: 1,
		},
		{
			Name:      "TPMSuccess",
			BitOffset: 3,
		},
		{
			Name:      "Force Anchor Boot",
			BitOffset: 4,
		},
		{
			Name:      "Measured",
			BitOffset: 5,
		},
		{
			Name:      "Verified",
			BitOffset: 6,
		},
		{
			Name:      "ModuleRevoked",
			BitOffset: 7,
		},
		{
			Name:      "<reserved>",
			BitOffset: 8,
		},
		{
			Name:      "BootGuardCapability",
			BitOffset: 32,
		},
		{
			Name:      "<reserved>",
			BitOffset: 33,
		},
		{
			Name:      "ServerTXTCapability",
			BitOffset: 34,
		},
		{
			Name:      "No Reset Secrets Protection",
			BitOffset: 35,
		},
		{
			Name:      "<reserved>",
			BitOffset: 36,
		},
	}
	return CalculateRegisterFields(reg.Raw(), reg.BitSize(), fieldsRaw)
}

// Value returns the raw value wrapped into an interface.
func (reg BTGSACMInfo) Value() interface{} {
	return reg.Raw()
}

func (reg BTGSACMInfo) Raw() uint64 {
	return uint64(reg)
}

func (reg BTGSACMInfo) NEMEnabled() bool {
	return reg&0x1 != 0
}

func (reg BTGSACMInfo) TPMType() TPMType {
	return TPMType((reg >> 1) & 0x3)
}

func (reg BTGSACMInfo) TPMSuccess() bool {
	return (reg>>3)&0x1 != 0
}

func (reg BTGSACMInfo) ForceAnchorBoot() bool {
	return (reg>>4)&0x1 != 0
}

func (reg BTGSACMInfo) Measured() bool {
	return (reg>>5)&0x1 != 0
}

func (reg BTGSACMInfo) Verified() bool {
	return (reg>>6)&0x1 != 0
}

func (reg BTGSACMInfo) ModuleRevoked() bool {
	return (reg>>7)&0x1 != 0
}

func (reg BTGSACMInfo) BootGuardCapability() bool {
	return (reg>>32)&0x1 != 0
}

func (reg BTGSACMInfo) ServerTXTCapability() bool {
	return (reg>>34)&0x1 != 0
}

func (reg BTGSACMInfo) NoResetSecretsProtection() bool {
	return (reg>>35)&0x1 != 0
}

var _ RawRegister64 = ParseBTGSACMInfo(0)

// ReadBTGSACMInfo reads IA32FeatureControl MSR register
func ReadBTGSACMInfo(msrReader MSRReader) (BTGSACMInfo, error) {
	value, err := msrReader.Read(BTGSACMInfoRegisterOffset)
	if err != nil {
		return 0, err
	}
	return ParseBTGSACMInfo(value), nil
}

// ParseBTGSACMInfo returns BootGuardPBEC from a raw 64bit value
func ParseBTGSACMInfo(raw uint64) BTGSACMInfo {
	return BTGSACMInfo(raw)
}

// FindBTGSACMInfo returns BTGSACMInfo register if found
func FindBTGSACMInfo(regs Registers) (BTGSACMInfo, bool) {
	r := regs.Find(BTGSACMInfoRegisterID)
	if r == nil {
		return 0, false
	}
	return r.(BTGSACMInfo), true
}
