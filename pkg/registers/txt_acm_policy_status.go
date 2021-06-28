package registers

import (
	"bytes"
	"encoding/binary"
	"io"
)

const AcmPolicyStatusRegisterID RegisterID = "ACM_POLICY_STATUS"
const ACMPolicyStatusRegisterOffset = 0x378

type BackupAction uint8

const (
	BackupActionMemoryPowerDown BackupAction = iota
	BackupActionBtGUnbreakableShutdown
	BackupActionPFRRecovery
	BackupActionReserved
)

type MemoryScrubbingPolicy uint8

const (
	MemoryScrubbingPolicyDefault MemoryScrubbingPolicy = iota
	MemoryScrubbingPolicyBIOS
	MemoryScrubbingPolicyACM
	MemoryScrubbingPolicyUnknown
)

type SCRTMStatus uint8

const (
	SCRTMStatusNone SCRTMStatus = 0
	SCRTMStatusBtG  SCRTMStatus = 1
	SCRTMStatusTXT  SCRTMStatus = 2
	SCRTMStatusPFR  SCRTMStatus = 4
)

type TPMStartupLocality uint8

const (
	TPMStartupLocality0 TPMStartupLocality = iota
	TPMStartupLocality3
)

type ACMPolicyStatus uint64

func (reg ACMPolicyStatus) ID() RegisterID {
	return AcmPolicyStatusRegisterID
}

func (reg ACMPolicyStatus) Raw() uint64 {
	return uint64(reg)
}

func (reg ACMPolicyStatus) BitSize() uint8 {
	return 64
}

func (reg ACMPolicyStatus) Address() uint64 {
	return TxtPublicSpace + ACMPolicyStatusRegisterOffset
}

func (reg ACMPolicyStatus) Fields() []Field {
	fieldsRaw := []FieldDescription{
		{
			Name:      "Key Manifest ID",
			BitOffset: 0,
		},
		{
			Name:      "BP.TYPE.M – BtG measures IBB into the TPM",
			BitOffset: 4,
		},
		{
			Name:      "BP.TYPE.V – BtG verifies IBB",
			BitOffset: 5,
		},
		{
			Name:      "BP.TYPE.HAP – Indicates HAP platform",
			BitOffset: 6,
		},
		{
			Name:      "BP.TYPE.T – Indicates TXT supported",
			BitOffset: 7,
		},
		{
			Name:      "<reserved>",
			BitOffset: 8,
		},
		{
			Name:      "BP.RSTR.DCD – Disable CPU debug",
			BitOffset: 9,
		},
		{
			Name:      "BP.RSTR.DBI – Disable BSP init",
			BitOffset: 10,
		},
		{
			Name:      "BP.RSTR.PBE Protect BIOS environment",
			BitOffset: 11,
		},
		{
			Name:      "<reserved>",
			BitOffset: 12,
		},
		{
			Name:      "TPM type",
			BitOffset: 13,
		},
		{
			Name:      "TPM Success",
			BitOffset: 15,
		},
		{
			Name:      "<reserved>",
			BitOffset: 16,
		},
		{
			Name:      "Backup action",
			BitOffset: 19,
		},
		{
			Name:      "TXT profile selection",
			BitOffset: 20,
		},
		{
			Name:      "Memory scrubbing Policy",
			BitOffset: 25,
		},
		{
			Name:      "<reserved>",
			BitOffset: 27,
		},
		{
			Name:      "IBB DMA Protection",
			BitOffset: 29,
		},
		{
			Name:      "<reserved>",
			BitOffset: 30,
		},
		{
			Name:      "S-CRTM Status",
			BitOffset: 32,
		},
		{
			Name:      "CPU Co-signing Enabled",
			BitOffset: 35,
		},
		{
			Name:      "TPM Startup locality",
			BitOffset: 36,
		},
		{
			Name:      "<reserved>",
			BitOffset: 37,
		},
	}

	return CalculateRegisterFields(reg.Raw(), reg.BitSize(), fieldsRaw)
}

func (reg ACMPolicyStatus) KMID() uint8 {
	// bits 0-3 (Key Manifest ID)
	return uint8(reg & 0x7)
}

func (reg ACMPolicyStatus) BootPolicyM() bool {
	// bit 4 (BtG measures IBB into the TPM)
	return (reg>>4)&0x1 != 0
}

func (reg ACMPolicyStatus) BootPolicyV() bool {
	// bit 5 (BtG verifies IBB)
	return (reg>>5)&0x1 != 0
}

func (reg ACMPolicyStatus) BootPolicyHAP() bool {
	// bit 6 (Indicates HAP platform)
	return (reg>>6)&0x1 != 0
}

func (reg ACMPolicyStatus) BootPolicyT() bool {
	// bit 7 (Indicates TXT supported)
	return (reg>>7)&0x1 != 0
}

func (reg ACMPolicyStatus) BootPolicyDCD() bool {
	// bit 9 (Disable CPU debug)
	return (reg>>9)&0x1 != 0
}

func (reg ACMPolicyStatus) BootPolicyDBI() bool {
	// bit 10 (Disable BSP init)
	return (reg>>10)&0x1 != 0
}

func (reg ACMPolicyStatus) BootPolicyPBE() bool {
	// bit 11 (Protect BIOS environment)
	return (reg>>11)&0x1 != 0
}

func (reg ACMPolicyStatus) TPMType() TPMType {
	// bits 13-14
	return TPMType((reg >> 13) & 0x3)
}

func (reg ACMPolicyStatus) TPMSuccess() bool {
	// bit 15
	return (reg>>15)&0x1 != 0
}

func (reg ACMPolicyStatus) BootPolicyP() bool {
	// bit 17 (Indicates PFR supported)
	return (reg>>17)&0x1 != 0
}

func (reg ACMPolicyStatus) BackupAction() BackupAction {
	// bit 18-19
	return BackupAction((reg >> 18) & 0x3)
}

func (reg ACMPolicyStatus) TXTProfileSelection() uint8 {
	// bits 20-24
	return uint8(reg >> 20)
}

func (reg ACMPolicyStatus) MemoryScrubbingPolicy() MemoryScrubbingPolicy {
	// bits 25-26
	return MemoryScrubbingPolicy((reg >> 25) & 0x3)
}

func (reg ACMPolicyStatus) IBBDmaProtection() bool {
	// bit 29
	return (reg>>25)&0x1 != 0
}

func (reg ACMPolicyStatus) SCRTMStatus() SCRTMStatus {
	// bit 32:34
	return SCRTMStatus((reg >> 32) & 0x7)
}

func (reg ACMPolicyStatus) CPUCoSigningEnabled() bool {
	// bit 35
	return (reg>>35)&0x1 != 0
}

func (reg ACMPolicyStatus) TPMStartupLocality() TPMStartupLocality {
	// bit 36
	bitSet := (reg>>36)&0x1 != 0
	if !bitSet {
		return TPMStartupLocality3
	}
	return TPMStartupLocality0
}

var _ RawRegister64 = ParseACMPolicyStatusRegister(0)

// ReadACMPolicyStatusRegister reads the raw ACM policy status register from TXT config
func ReadACMPolicyStatusRegister(data TXTConfigSpace) (ACMPolicyStatus, error) {
	var u64 uint64
	buf := bytes.NewReader(data)
	_, err := buf.Seek(ACMPolicyStatusRegisterOffset, io.SeekStart)
	if err != nil {
		return 0, err
	}
	err = binary.Read(buf, binary.LittleEndian, &u64)
	if err != nil {
		return 0, err
	}
	return ACMPolicyStatus(u64), nil
}

// ParseACMPolicyStatusRegister returns ACMPolicyStatus from a raw 64bit value
func ParseACMPolicyStatusRegister(raw uint64) ACMPolicyStatus {
	return ACMPolicyStatus(raw)
}

// FindACMPolicyStatus returns ACMPolicyStatus register if found
func FindACMPolicyStatus(regs Registers) (ACMPolicyStatus, bool) {
	r := regs.Find(AcmPolicyStatusRegisterID)
	if r == nil {
		return 0, false
	}
	return r.(ACMPolicyStatus), true
}
