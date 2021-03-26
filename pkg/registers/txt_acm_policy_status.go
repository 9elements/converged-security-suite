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

func (reg ACMPolicyStatus) Fields() []Field {
	fieldsRaw := []fieldDescription{
		{
			name:      "Key Manifest ID",
			bitOffset: 0,
		},
		{
			name:      "BP.TYPE.M – BtG measures IBB into the TPM",
			bitOffset: 4,
		},
		{
			name:      "BP.TYPE.V – BtG verifies IBB",
			bitOffset: 5,
		},
		{
			name:      "BP.TYPE.HAP – Indicates HAP platform",
			bitOffset: 6,
		},
		{
			name:      "BP.TYPE.T – Indicates TXT supported",
			bitOffset: 7,
		},
		{
			name:      "<reserved>",
			bitOffset: 8,
		},
		{
			name:      "BP.RSTR.DCD – Disable CPU debug",
			bitOffset: 9,
		},
		{
			name:      "BP.RSTR.DBI – Disable BSP init",
			bitOffset: 10,
		},
		{
			name:      "BP.RSTR.PBE Protect BIOS environment",
			bitOffset: 11,
		},
		{
			name:      "<reserved>",
			bitOffset: 12,
		},
		{
			name:      "TPM type",
			bitOffset: 13,
		},
		{
			name:      "TPM Success",
			bitOffset: 15,
		},
		{
			name:      "<reserved>",
			bitOffset: 16,
		},
		{
			name:      "Backup action",
			bitOffset: 19,
		},
		{
			name:      "TXT profile selection",
			bitOffset: 20,
		},
		{
			name:      "Memory scrubbing Policy",
			bitOffset: 25,
		},
		{
			name:      "<reserved>",
			bitOffset: 27,
		},
		{
			name:      "IBB DMA Protection",
			bitOffset: 29,
		},
		{
			name:      "<reserved>",
			bitOffset: 30,
		},
		{
			name:      "S-CRTM Status",
			bitOffset: 32,
		},
		{
			name:      "CPU Co-signing Enabled",
			bitOffset: 35,
		},
		{
			name:      "TPM Startup locality",
			bitOffset: 36,
		},
		{
			name:      "<reserved>",
			bitOffset: 37,
		},
	}

	return calculateRegisterFields(reg.Raw(), reg.BitSize(), fieldsRaw)
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
