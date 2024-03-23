package tools

import (
	"bytes"
	"crypto"
	"encoding/binary"
	"fmt"
	"io"
	"strconv"
	"strings"

	"github.com/google/go-tpm/tpm2"

	log "github.com/sirupsen/logrus"
)

// HashAlgMap exports map from crypto.Hash to LCPPol2Hash for parsing manual input to LCPPolicy2
var HashAlgMap = map[crypto.Hash]tpm2.Algorithm{
	crypto.SHA1:   0x04,
	crypto.SHA256: 0x0B,
	crypto.SHA384: 0x0C,
}

// LCPPolicyType exports the PolicyType type for external use
type LCPPolicyType uint8

func (pt LCPPolicyType) String() string {
	if pt == 1 {
		return string("Any")
	} else if pt == 0 {
		return string("List")
	} else {
		return string("Unknown")
	}
}

// LCPPol2Sig represents LCPPol2.LcpSignAlgMask options
type LCPPol2Sig uint32

const (
	// RSA2048SHA1 as defined in Document 315168-016 Chapter D.1.3 LCP_POLICY2
	RSA2048SHA1 LCPPol2Sig = 0x00000004
	// RSA2048SHA256 as defined in Document 315168-016 Chapter D.1.3 LCP_POLICY2
	RSA2048SHA256 LCPPol2Sig = 0x00000008
	// RSA3072SHA256 as defined in Document 315168-016 Chapter D.1.3 LCP_POLICY2
	RSA3072SHA256 LCPPol2Sig = 0x00000040
	// RSA3072SHA384 as defined in Document 315168-016 Chapter D.1.3 LCP_POLICY2
	RSA3072SHA384 LCPPol2Sig = 0x00000080
	// ECDSAP256SHA256 as defined in Document 315168-016 Chapter D.1.3 LCP_POLICY2
	ECDSAP256SHA256 LCPPol2Sig = 0x00001000
	// ECDSAP384SHA384 as defined in Document 315168-016 Chapter D.1.3 LCP_POLICY2
	ECDSAP384SHA384 LCPPol2Sig = 0x00002000
	// SM2SM2CurveSM3 as defined in Document 315168-016 Chapter D.1.3 LCP_POLICY2
	SM2SM2CurveSM3 LCPPol2Sig = 0x00010000
)

func (ls LCPPol2Sig) String() string {
	var b strings.Builder
	if (1 >> (ls & RSA2048SHA1)) == 0 {
		b.WriteString("RSA2048SHA1 + ")
	}
	if (1 >> (ls & RSA2048SHA256)) == 0 {
		b.WriteString("RSA2048SHA256 + ")
	}
	if (1 >> (ls & RSA3072SHA256)) == 0 {
		b.WriteString("RSA3072SHA256 + ")
	}
	if (1 >> (ls & RSA3072SHA384)) == 0 {
		b.WriteString("RSA3072SHA384 + ")
	}
	if (1 >> (ls & ECDSAP256SHA256)) == 0 {
		b.WriteString("ECDSAP256SHA256 + ")
	}
	if (1 >> (ls & ECDSAP384SHA384)) == 0 {
		b.WriteString("ECDSAP384SHA384 + ")
	}
	if (1 >> (ls & SM2SM2CurveSM3)) == 0 {
		b.WriteString("SM2SM2CurveSM3")
	}
	ret := strings.TrimSuffix(b.String(), "+ ")
	return ret
}

// SignMaskMap exports map to convert string to type LCPPol2Sig for file parsing
var SignMaskMap = map[string]LCPPol2Sig{
	"RSA2048SHA1":     RSA2048SHA1,
	"RSA2048SHA256":   RSA2048SHA256,
	"RSA3072SHA256":   RSA3072SHA256,
	"RSA3072SHA384":   RSA3072SHA384,
	"ECDSAP256SHA256": ECDSAP256SHA256,
	"ECDSAP384SHA384": ECDSAP384SHA384,
}

const (
	// LCPPol2HashMaskSHA1 exports SHA1 definition for LCPPolicy2.LcpHashMapAlg
	LCPPol2HashMaskSHA1 uint16 = 0x0001

	// LCPPol2HashMaskSHA256 exports SHA256 definition for LCPPolicy2.LcpHashMapAlg
	LCPPol2HashMaskSHA256 uint16 = 0x0008

	// LCPPol2HashMaskSHA384 exports SHA384 definition for LCPPolicy2.LcpHashMapAlg
	LCPPol2HashMaskSHA384 uint16 = 0x0040
)

// HashMaskMap exports map to convert string to type LCPPol2HashMask for file parsing
var HashMaskMap = map[string]uint16{
	"SHA1":   LCPPol2HashMaskSHA1,
	"SHA256": LCPPol2HashMaskSHA256,
	"SHA384": LCPPol2HashMaskSHA384,
}

const (
	// LCPPolicyVersion2 as defined in Document 315168-016 Chapter 3.2.1 LCP Policy
	LCPPolicyVersion2 uint16 = 0x0204
	// LCPPolicyVersion3 as defined in Document 315168-016 Chapter 3.2.1 LCP Policy
	LCPPolicyVersion3 uint16 = 0x0300
	// LCPPolicyTypeAny as defined in Document 315168-016 Chapter D LCP Data Structures
	LCPPolicyTypeAny LCPPolicyType = 1
	// LCPPolicyTypeList as defined in Document 315168-016 Chapter D LCP Data Structures
	LCPPolicyTypeList LCPPolicyType = 0
	// LCPMaxLists as defined in Document 315168-016 Chapter D LCP Data Structures
	LCPMaxLists uint = 8
	// SHA1DigestSize as defined in Document 315168-016 Chapter D.1.3 LCP_POLICY2
	SHA1DigestSize uint = 20
	// SHA256DigestSize as defined in Document 315168-016 Chapter D.1.3 LCP_POLICY2
	SHA256DigestSize uint = 32
	// SHA384DigestSize as defined in Document 315168-016 Chapter D.1.3 LCP_POLICY2
	SHA384DigestSize uint = 48
	// SHA512DigestSize FIXME
	SHA512DigestSize uint = 64
	// SM3DigestSize as defined in Document 315168-016 Chapter D.1.3 LCP_POLICY2
	SM3DigestSize uint = 32
	// LCPDataFileSignature as defined in Document 315168-016 Chapter D.2 LCP_POLICY_DATA
	LCPDataFileSignature string = "Intel(R) TXT LCP_POLICY_DATA\x00\x00\x00\x00"

	// LCPSignatureAlgNone FIXME
	LCPSignatureAlgNone uint8 = 0
	// LCPSignatureAlgRSAPKCS15 FIXME
	LCPSignatureAlgRSAPKCS15 uint8 = 1

	// LCPPolicyElementMLE as defined in Document 315168-016 Chapter D.4.4 LCP_MLE_ELEMENT
	LCPPolicyElementMLE uint32 = 0
	// LCPPolicyElementPCONF as defined in Document 315168-016 Chapter D.4.5 LCP_PCONF_ELEMENT
	LCPPolicyElementPCONF uint32 = 1
	// LCPPolicyElementSBIOS FIXME
	LCPPolicyElementSBIOS uint32 = 2
	// LCPPolicyElementCustom as defined in Document 315168-016 Chapter D.4.6 LCP_CUSTOM_ELEMENT
	LCPPolicyElementCustom uint32 = 3
	// LCPPolicyElementMLE2 as defined in Document 315168-016 Chapter D.4.7 LCP_MLE_ELEMENT2
	LCPPolicyElementMLE2 uint32 = 0x10
	// LCPPolicyElementPCONF2 as defined in Document 315168-016 Chapter D.4.8 LCP_PCONF_ELEMENT2
	LCPPolicyElementPCONF2 uint32 = 0x11
	// LCPPolicyElementSBIOS2 FIXME
	LCPPolicyElementSBIOS2 uint32 = 0x12
	// LCPPolicyElementSTM2 as defined in Document 315168-016 Chapter D.4.9 LCP_STM_ELEMENT2
	LCPPolicyElementSTM2 uint32 = 0x14

	// LCPPolHAlgSHA1 Document 315168-016 Chapter D.1 LCP_POLICY
	LCPPolHAlgSHA1 uint8 = 0

	// LCPPolicyControlNPW as defined in Document 315168-013 Chapter 3.2.2 PolicyControl Field for LCP_POLTYPE_LIST
	LCPPolicyControlNPW uint32 = 0x00000001
	// LCPPolicyControlSinitCaps as defined in Document 315168-013 Chapter 3.2.2 PolicyControl Field for LCP_POLTYPE_LIST
	LCPPolicyControlSinitCaps uint32 = 0x00000002
	// LCPPolicyControlOwnerEnforced as defined in Document 315168-013 Chapter 3.2.2 PolicyControl Field for LCP_POLTYPE_LIST
	LCPPolicyControlOwnerEnforced uint32 = 0x00000004
	// LCPPolicyControlAuxDelete as defined in Document 315168-013 Chapter 3.3.2 LCP Policy 2
	LCPPolicyControlAuxDelete uint32 = 0x80000000
)

// PolicyControlMap exports map to convert string to type PoliyControl for file parsing
var PolicyControlMap = map[string]uint32{
	"NPW":           0x00000001,
	"SinitCaps":     0x00000002,
	"OwnerEnforced": 0x00000004,
	"AuxDelete":     0x80000000,
}

// LCPHash holds one of the supported hashes
type LCPHash struct {
	Sha1   *[SHA1DigestSize]uint8
	Sha256 *[SHA256DigestSize]uint8
	Sha384 *[SHA384DigestSize]uint8
	Sha512 *[SHA512DigestSize]uint8
	SM3    *[SM3DigestSize]uint8
}

// LCPPolicyElement represents a policy element as defined in Document 315168-016 Chapter D.4 LCP_POLICY_ELEMENT
type LCPPolicyElement struct {
	Size             uint32
	Type             uint32
	PolicyEltControl uint32
	MLE              *LCPPolicyMLE
	SBIOS            *LCPPolicySBIOS
	PCONF            *LCPPolicyPCONF
	Custom           *LCPPolicyCustom
}

// LCPPolicyMLE represents a MLE policy element as defined in Document 315168-016 Chapter D.4.4 LCP_MLE_ELEMENT
type LCPPolicyMLE struct {
	SINITMinVersion uint8
	HashAlg         uint8
	NumHashes       uint16
	Hashes          [][20]byte
}

// LCPPolicySBIOS represents a SBIOS policy element
type LCPPolicySBIOS struct {
	HashAlg      uint8
	Reserved1    [3]uint8
	FallbackHash LCPHash
	Reserved2    uint16
	NumHashes    uint16
	Hashes       []LCPHash
}

// LCPPolicyPCONF represents a PCONF policy element
type LCPPolicyPCONF struct {
	NumPCRInfos uint16
	PCRInfos    []TPMPCRInfoShort
}

// TPMPCRInfoShort rFIXME
type TPMPCRInfoShort struct {
	// TPM_PCR_SELECTION
	PCRSelect []int
	// TPM_LOCALITY_SELECTION
	LocalityAtRelease uint8
	// TPM_COMPOSITE_HASH
	DigestAtRelease [20]byte
}

// LCPPolicyCustom represents a custom policy element
type LCPPolicyCustom struct {
	UUID LCPUUID
	Data []byte
}

// LCPUUID represents an UUID
type LCPUUID struct {
	data1 uint32
	data2 uint16
	data3 uint16
	data4 uint16
	data5 [6]uint8
}

// LCPPolicyList2 as defined in Document 315168-016 Chapter D.3.2.1 LCP_POLICY_LIST2 Structure
type LCPPolicyList2 struct {
	Version           uint16
	SignaturAlg       uint16
	PolicyElementSize uint32
	PolicyElements    []LCPPolicyElement
}

// LCPSignature as defined in Document 315168-016 Chapter D.3.2.1 LCP_POLICY_LIST2 Structure
type LCPSignature struct {
	RevocationCounter uint16
	PubkeySize        uint16
	PubkeyValue       []byte
	SigBlock          []byte
}

// LCPPolicyList FIXME not in Document 315168-016
type LCPPolicyList struct {
	Version           uint16
	Reserved          uint8
	SignaturAlg       uint8
	PolicyElementSize uint32
	PolicyElements    []LCPPolicyElement
	Signature         *LCPSignature
}

// LCPList as defined in Document 315168-016 Chapter D.3.2.3 LCP_LIST
type LCPList struct {
	TPM12PolicyList LCPPolicyList
	TPM20PolicyList LCPPolicyList2
}

// PolicyControl as defined in Document 315168-016 Chapter D.1.1 PolicyControl
type PolicyControl struct {
	NPW           bool
	OwnerEnforced bool
	AuxDelete     bool
	SinitCaps     bool
}

// ApprovedHashAlgorithm as defined in Document 315168-016 Chapter D.1.3 LCP_POLICY2
type ApprovedHashAlgorithm struct {
	SHA1   bool
	SHA256 bool
	SHA384 bool
	SM3    bool
}

// ApprovedSignatureAlogrithm as defined in Document 315168-016 Chapter D.1.3 LCP_POLICY2
type ApprovedSignatureAlogrithm struct {
	RSA2048SHA1     bool
	RSA2048SHA256   bool
	RSA3072SHA256   bool
	RSA3072SHA384   bool
	ECDSAP256SHA256 bool
	ECDSAP384SHA384 bool
	SM2SM2CurveSM3  bool
}

// LCPPolicy as defined in Document 315168-016 Chapter D.1.2 LCP_POLICY
type LCPPolicy struct {
	Version                uint16 // < 0x0204
	HashAlg                uint8
	PolicyType             LCPPolicyType
	SINITMinVersion        uint8
	Reserved               uint8
	DataRevocationCounters [LCPMaxLists]uint16
	PolicyControl          uint32
	MaxSINITMinVersion     uint8
	Reserved1              uint8
	Reserved2              uint16
	Reserved3              uint32
	PolicyHash             [20]byte
}

// LCPPolicy2 as defined in Document 315168-016 Chapter D.1.3 LCP_POLICY2
type LCPPolicy2 struct {
	Version                uint16 // < 0x0302
	HashAlg                tpm2.Algorithm
	PolicyType             LCPPolicyType
	SINITMinVersion        uint8
	DataRevocationCounters [LCPMaxLists]uint16
	PolicyControl          uint32
	MaxSINITMinVersion     uint8 // v2.0 - Only PO index, reserved for PS
	Reserved               uint8 // v2.0 - Only PO index, reserved for PS
	LcpHashAlgMask         uint16
	LcpSignAlgMask         LCPPol2Sig
	Reserved2              uint32
	PolicyHash             [32]byte
}

// LCPPolicyData FIXME
type LCPPolicyData struct {
	FileSignature [32]uint8
	Reserved      [3]uint8
	NumLists      uint8
	PolicyLists   []LCPList
}

// ParsePolicyControl TODO needs to be reverse engineered
func (p *LCPPolicy) ParsePolicyControl() PolicyControl {
	var polCtrl PolicyControl
	polCtrl.NPW = (p.PolicyControl>>0)&1 != 0
	polCtrl.SinitCaps = (p.PolicyControl>>1)&1 != 0
	polCtrl.AuxDelete = (p.PolicyControl>>31)&1 != 0
	polCtrl.OwnerEnforced = (p.PolicyControl>>2)&1 != 0
	return polCtrl
}

// ParsePolicyControl2 TODO needs to be reverse engineered
func (p *LCPPolicy2) ParsePolicyControl2() PolicyControl {
	var polCtrl PolicyControl
	polCtrl.NPW = (p.PolicyControl>>0)&1 != 0
	polCtrl.SinitCaps = (p.PolicyControl>>1)&1 != 0
	polCtrl.AuxDelete = (p.PolicyControl>>31)&1 != 0
	polCtrl.OwnerEnforced = (p.PolicyControl>>2)&1 != 0
	return polCtrl
}

// ParseApprovedHashAlgorithm returns the supported hash algorithms
func (p *LCPPolicy2) ParseApprovedHashAlgorithm() ApprovedHashAlgorithm {
	var hashAlgs ApprovedHashAlgorithm
	hashAlgs.SHA1 = (p.LcpHashAlgMask>>0)&1 != 0
	hashAlgs.SHA256 = (p.LcpHashAlgMask>>3)&1 != 0
	hashAlgs.SHA384 = (p.LcpHashAlgMask>>6)&1 != 0
	hashAlgs.SM3 = (p.LcpHashAlgMask>>5)&1 != 0
	return hashAlgs
}

// ParseApprovedSignatureAlgorithm returns the supported signature algorithms
func (p *LCPPolicy2) ParseApprovedSignatureAlgorithm() ApprovedSignatureAlogrithm {
	var signatureAlgs ApprovedSignatureAlogrithm
	signatureAlgs.RSA2048SHA1 = (p.LcpSignAlgMask>>2)&1 != 0
	signatureAlgs.RSA2048SHA256 = (p.LcpSignAlgMask>>3)&1 != 0
	signatureAlgs.RSA3072SHA256 = (p.LcpSignAlgMask>>6)&1 != 0
	signatureAlgs.RSA3072SHA384 = (p.LcpSignAlgMask>>7)&1 != 0
	signatureAlgs.ECDSAP256SHA256 = (p.LcpSignAlgMask>>12)&1 != 0
	signatureAlgs.ECDSAP384SHA384 = (p.LcpSignAlgMask>>13)&1 != 0
	signatureAlgs.SM2SM2CurveSM3 = (p.LcpSignAlgMask>>16)&1 != 0
	return signatureAlgs
}

func parsePolicy(policy []byte) (*LCPPolicy, error) {
	var pol LCPPolicy
	buf := bytes.NewReader(policy)
	err := binary.Read(buf, binary.LittleEndian, &pol.Version)
	if err != nil {
		return nil, err
	}
	err = binary.Read(buf, binary.LittleEndian, &pol.HashAlg)
	if err != nil {
		return nil, err
	}
	err = binary.Read(buf, binary.LittleEndian, &pol.PolicyType)
	if err != nil {
		return nil, err
	}
	err = binary.Read(buf, binary.LittleEndian, &pol.SINITMinVersion)
	if err != nil {
		return nil, err
	}
	err = binary.Read(buf, binary.LittleEndian, &pol.Reserved)
	if err != nil {
		return nil, err
	}
	err = binary.Read(buf, binary.LittleEndian, &pol.DataRevocationCounters)
	if err != nil {
		return nil, err
	}
	err = binary.Read(buf, binary.LittleEndian, &pol.PolicyControl)
	if err != nil {
		return nil, err
	}
	err = binary.Read(buf, binary.LittleEndian, &pol.MaxSINITMinVersion)
	if err != nil {
		return nil, err
	}
	err = binary.Read(buf, binary.LittleEndian, &pol.Reserved1)
	if err != nil {
		return nil, err
	}
	err = binary.Read(buf, binary.LittleEndian, &pol.Reserved2)
	if err != nil {
		return nil, err
	}
	err = binary.Read(buf, binary.LittleEndian, &pol.Reserved3)
	if err != nil {
		return nil, err
	}
	err = binary.Read(buf, binary.LittleEndian, &pol.PolicyHash)
	if err != nil {
		return nil, err
	}

	return &pol, nil
}

func parsePolicy2(policy []byte) (*LCPPolicy2, error) {
	var pol2 LCPPolicy2
	buf := bytes.NewReader(policy)
	err := binary.Read(buf, binary.LittleEndian, &pol2.Version)
	if err != nil {
		return nil, err
	}
	err = binary.Read(buf, binary.LittleEndian, &pol2.HashAlg)
	if err != nil {
		return nil, err
	}
	err = binary.Read(buf, binary.LittleEndian, &pol2.PolicyType)
	if err != nil {
		return nil, err
	}
	err = binary.Read(buf, binary.LittleEndian, &pol2.SINITMinVersion)
	if err != nil {
		return nil, err
	}
	err = binary.Read(buf, binary.LittleEndian, &pol2.DataRevocationCounters)
	if err != nil {
		return nil, err
	}
	err = binary.Read(buf, binary.LittleEndian, &pol2.PolicyControl)
	if err != nil {
		return nil, err
	}
	err = binary.Read(buf, binary.LittleEndian, &pol2.MaxSINITMinVersion)
	if err != nil {
		return nil, err
	}
	err = binary.Read(buf, binary.LittleEndian, &pol2.Reserved)
	if err != nil {
		return nil, err
	}
	err = binary.Read(buf, binary.LittleEndian, &pol2.LcpHashAlgMask)
	if err != nil {
		return nil, err
	}
	err = binary.Read(buf, binary.LittleEndian, &pol2.LcpSignAlgMask)
	if err != nil {
		return nil, err
	}
	err = binary.Read(buf, binary.LittleEndian, &pol2.Reserved2)
	if err != nil {
		return nil, err
	}

	h, err := pol2.HashAlg.Hash()
	if err != nil {
		return nil, err
	}
	hash := make([]byte, h.Size())
	err = binary.Read(buf, binary.LittleEndian, &hash)
	if err != nil && err != io.EOF {
		return nil, err
	}
	copy(pol2.PolicyHash[:], hash[:h.Size()])

	return &pol2, nil
}

// ParsePolicy generates one of LCPPolicy or LCPPolicy2
func ParsePolicy(policy []byte) (*LCPPolicy, *LCPPolicy2, error) {
	var version uint16
	buf := bytes.NewReader(policy)
	err := binary.Read(buf, binary.LittleEndian, &version)
	if err != nil {
		return nil, nil, err
	}
	if version <= LCPPolicyVersion2 {
		pol, err := parsePolicy(policy)
		return pol, nil, err
	} else if version >= LCPPolicyVersion3 {
		pol, err := parsePolicy2(policy)
		return nil, pol, err
	}

	return nil, nil, fmt.Errorf("can't parse LCP Policy")
}

func parsePolicyElement(buf *bytes.Reader, element *LCPPolicyElement) error {
	err := binary.Read(buf, binary.LittleEndian,
		&element.Size)
	if err != nil {
		return err
	}
	err = binary.Read(buf, binary.LittleEndian,
		&element.Type)
	if err != nil {
		return err
	}
	err = binary.Read(buf, binary.LittleEndian,
		&element.PolicyEltControl)
	if err != nil {
		return err
	}

	switch element.Type {
	case LCPPolicyElementMLE:
		var pol LCPPolicyMLE
		err = parsePolicyElementMLE(buf, &pol)
		if err != nil {
			return err
		}
		element.MLE = &pol
	case LCPPolicyElementSBIOS:
		var pol LCPPolicySBIOS
		err = parsePolicyElementSBIOS(buf, &pol)
		if err != nil {
			return err
		}
		element.SBIOS = &pol
	case LCPPolicyElementPCONF:
		var pol LCPPolicyPCONF
		err = parsePolicyElementPCONF(buf, &pol)
		if err != nil {
			return err
		}
		element.PCONF = &pol
	case LCPPolicyElementCustom:
		var pol LCPPolicyCustom
		err = parsePolicyElementCustom(buf, int(element.Size)-16, &pol)
		if err != nil {
			return err
		}
		element.Custom = &pol
	default:
		return fmt.Errorf("unknown policy element type: %d, See: Intel TXT Software Development Guide, Document: 315168-010, P. 116", element.Type)
	}

	return nil
}

func parsePolicyElementMLE(buf *bytes.Reader, pol *LCPPolicyMLE) error {
	err := binary.Read(buf, binary.LittleEndian,
		&pol.SINITMinVersion)
	if err != nil {
		return err
	}

	err = binary.Read(buf, binary.LittleEndian,
		&pol.HashAlg)
	if err != nil {
		return err
	}

	err = binary.Read(buf, binary.LittleEndian,
		&pol.NumHashes)
	if err != nil {
		return err
	}

	pol.Hashes = make([][20]byte, pol.NumHashes)
	for i := 0; i < int(pol.NumHashes); i++ {
		if err := binary.Read(buf, binary.LittleEndian, &pol.Hashes[i]); err != nil {
			return err
		}
	}
	return nil
}

func parsePolicyElementSBIOS(buf *bytes.Reader, pol *LCPPolicySBIOS) error {
	err := binary.Read(buf, binary.LittleEndian,
		&pol.HashAlg)
	if err != nil {
		return err
	}

	err = binary.Read(buf, binary.LittleEndian,
		&pol.Reserved1)
	if err != nil {
		return err
	}

	err = parseLCPHash(buf, &pol.FallbackHash, pol.HashAlg)
	if err != nil {
		return err
	}

	err = binary.Read(buf, binary.LittleEndian,
		&pol.Reserved2)
	if err != nil {
		return err
	}

	err = binary.Read(buf, binary.LittleEndian,
		&pol.NumHashes)
	if err != nil {
		return err
	}

	pol.Hashes = make([]LCPHash, pol.NumHashes)
	for i := 0; i < int(pol.NumHashes); i++ {
		err = parseLCPHash(buf, &pol.Hashes[i], pol.HashAlg)
		if err != nil {
			return err
		}
	}

	return nil
}

func parsePolicyElementPCONF(buf *bytes.Reader, pol *LCPPolicyPCONF) error {
	err := binary.Read(buf, binary.LittleEndian,
		&pol.NumPCRInfos)
	if err != nil {
		return err
	}

	pol.PCRInfos = make([]TPMPCRInfoShort, pol.NumPCRInfos)
	for i := 0; i < int(pol.NumPCRInfos); i++ {
		err = parseTPMPCRInfoShort(buf, &pol.PCRInfos[i])
		if err != nil {
			return err
		}
	}

	return nil
}

func parseTPMPCRInfoShort(buf *bytes.Reader, info *TPMPCRInfoShort) error {
	var selSize uint16

	err := binary.Read(buf, binary.BigEndian,
		&selSize)
	if err != nil {
		return err
	}

	for i := 0; i < int(selSize); i++ {
		var b byte

		err = binary.Read(buf, binary.BigEndian,
			&b)
		if err != nil {
			return err
		}

		for j := 0; j < 8; j++ {
			if b&(1<<uint(j)) != 0 {
				info.PCRSelect = append(info.PCRSelect, i*8+j)
			}
		}
	}

	err = binary.Read(buf, binary.BigEndian,
		&info.LocalityAtRelease)
	if err != nil {
		return err
	}

	err = binary.Read(buf, binary.BigEndian,
		&info.DigestAtRelease)
	if err != nil {
		return err
	}

	return nil
}

func parsePolicyElementCustom(buf *bytes.Reader, size int, pol *LCPPolicyCustom) error {
	err := parseLCPUUID(buf, &pol.UUID)
	if err != nil {
		return err
	}

	pol.Data = make([]byte, size-16)
	err = binary.Read(buf, binary.LittleEndian,
		&pol.Data)
	if err != nil {
		return err
	}

	return nil
}

func parseLCPUUID(buf *bytes.Reader, uuid *LCPUUID) error {
	err := binary.Read(buf, binary.LittleEndian,
		&uuid.data1)
	if err != nil {
		return err
	}

	err = binary.Read(buf, binary.LittleEndian,
		&uuid.data2)
	if err != nil {
		return err
	}

	err = binary.Read(buf, binary.LittleEndian,
		&uuid.data3)
	if err != nil {
		return err
	}

	err = binary.Read(buf, binary.LittleEndian,
		&uuid.data4)
	if err != nil {
		return err
	}

	err = binary.Read(buf, binary.LittleEndian,
		&uuid.data5)
	if err != nil {
		return err
	}

	return nil
}

func parsePolicyList(buf *bytes.Reader, list *LCPPolicyList) error {
	err := binary.Read(buf, binary.LittleEndian,
		&list.Version)
	if err != nil {
		return err
	}

	err = binary.Read(buf, binary.LittleEndian,
		&list.Reserved)
	if err != nil {
		return err
	}

	err = binary.Read(buf, binary.LittleEndian,
		&list.SignaturAlg)
	if err != nil {
		return err
	}

	err = binary.Read(buf, binary.LittleEndian,
		&list.PolicyElementSize)
	if err != nil {
		return err
	}

	for i := 0; i < int(list.PolicyElementSize); {
		var elt LCPPolicyElement

		err = parsePolicyElement(buf, &elt)
		if err != nil {
			return err
		}

		list.PolicyElements = append(list.PolicyElements, elt)
		i += int(elt.Size)
	}

	switch list.SignaturAlg {
	case LCPSignatureAlgNone:
		// NOP
	case LCPSignatureAlgRSAPKCS15:
		var sig LCPSignature

		err = parseLCPSignature(buf, &sig)
		if err != nil {
			return err
		}
		list.Signature = &sig

	default:
		return fmt.Errorf("unknown signature algorithm: %x", list.SignaturAlg)
	}

	return nil
}

func parsePolicyList2(buf *bytes.Reader, list *LCPPolicyList2) error {
	err := binary.Read(buf, binary.LittleEndian,
		&list.Version)
	if err != nil {
		return err
	}

	err = binary.Read(buf, binary.LittleEndian,
		&list.SignaturAlg)
	if err != nil {
		return err
	}

	err = binary.Read(buf, binary.LittleEndian,
		&list.PolicyElementSize)
	if err != nil {
		return err
	}

	list.PolicyElements = make([]LCPPolicyElement, list.PolicyElementSize)
	for i := 0; i < int(list.PolicyElementSize); i++ {
		if err := parsePolicyElement(buf, &list.PolicyElements[i]); err != nil {
			return fmt.Errorf("unable to parse policy element %d: %w", i, err)
		}
	}

	return nil
}

func parseLCPSignature(buf *bytes.Reader, sig *LCPSignature) error {
	err := binary.Read(buf, binary.LittleEndian,
		&sig.RevocationCounter)
	if err != nil {
		return err
	}

	err = binary.Read(buf, binary.LittleEndian,
		&sig.PubkeySize)
	if err != nil {
		return err
	}

	sig.PubkeyValue = make([]byte, sig.PubkeySize)
	err = binary.Read(buf, binary.LittleEndian,
		&sig.PubkeyValue)
	if err != nil {
		return err
	}

	sig.SigBlock = make([]byte, sig.PubkeySize)
	err = binary.Read(buf, binary.LittleEndian,
		&sig.SigBlock)
	if err != nil {
		return err
	}

	return nil
}

func parseLCPHash(buf *bytes.Reader, hash *LCPHash, alg uint8) error {
	switch alg {
	case LCPPolHAlgSHA1:
		return parseLCPHash2(buf, hash, tpm2.AlgSHA1)
	default:
		return fmt.Errorf("unsupported hash algorithm: %x", alg)
	}
}

func parseLCPHash2(buf *bytes.Reader, hash *LCPHash, alg tpm2.Algorithm) error {
	h, err := alg.Hash()
	if err != nil {
		return err
	}
	hbyte := make([]byte, h.Size())
	err = binary.Read(buf, binary.LittleEndian, &hbyte)
	if err != nil {
		return err
	}
	switch alg {
	case tpm2.AlgSHA1:
		var tmp [SHA1DigestSize]byte
		copy(tmp[:], hbyte[:])
		hash.Sha1 = &tmp
	case tpm2.AlgSHA256:
		var tmp [SHA256DigestSize]byte
		copy(tmp[:], hbyte[:])
		hash.Sha256 = &tmp
	case tpm2.AlgSHA384:
		var tmp [SHA384DigestSize]byte
		copy(tmp[:], hbyte[:])
		hash.Sha384 = &tmp
	case tpm2.AlgSHA512:
		var tmp [SHA512DigestSize]byte
		copy(tmp[:], hbyte[:])
		hash.Sha512 = &tmp

		// case tpm2.AlgSM3:
		// copy(hash.sm3[:], hbyte[:h.Size()])

	default:
		return fmt.Errorf("unsupported hash algorithm: %x", alg)
	}

	return nil
}

// ParsePolicyData parses a raw copy of the LCP policy
func ParsePolicyData(policyData []byte) (*LCPPolicyData, error) {
	var polData LCPPolicyData

	buf := bytes.NewReader(policyData)
	err := binary.Read(buf, binary.LittleEndian, &polData.FileSignature)
	if err != nil {
		return nil, err
	}

	err = binary.Read(buf, binary.LittleEndian, &polData.Reserved)
	if err != nil {
		return nil, err
	}

	err = binary.Read(buf, binary.LittleEndian, &polData.NumLists)
	if err != nil {
		return nil, err
	}

	polData.PolicyLists = make([]LCPList, polData.NumLists)
	for i := 0; i < int(polData.NumLists); i++ {
		err = parsePolicyList(buf, &polData.PolicyLists[i].TPM12PolicyList)
		if err != nil {
			err = parsePolicyList2(buf, &polData.PolicyLists[i].TPM20PolicyList)
			if err != nil {
				return nil, err
			}
		}
	}

	return &polData, nil
}

// PrettyPrint prints the LCPHash in a human readable format
func (p *LCPHash) PrettyPrint() string {
	if p.Sha1 != nil {
		return fmt.Sprintf("%02x [SHA-1]", *p.Sha1)
	} else if p.Sha256 != nil {
		return fmt.Sprintf("%02x [SHA-256]", *p.Sha256)
	} else if p.Sha384 != nil {
		return fmt.Sprintf("%02x [SHA-384]", *p.Sha384)
	} else if p.Sha512 != nil {
		return fmt.Sprintf("%02x [SHA-512]", *p.Sha512)
		//} else if p.sm3 != nil {
		//	return fmt.Sprintf("% 02x [SM3]", *p.sm3)
	} else {
		return "(Invalid)"
	}
}

// PrettyPrint prints the LCPPolicyData in a human readable format
func (pd *LCPPolicyData) PrettyPrint() {
	log.Infof("Launch Control Policy Data")

	var fileSig string
	if bytes.Equal(pd.FileSignature[:], []uint8(LCPDataFileSignature)) {
		fileSig = "valid"
	} else {
		fileSig = "invalid"
	}
	log.Infof("File Signature % x (%s)", pd.FileSignature, fileSig)

	log.Info("LCP Policy Lists:")
	log.Infof("\tLists: %d", pd.NumLists)
	for idx, pol := range pd.PolicyLists {
		log.Infof("\tList %d:", idx)
		log.Infof("\t\tVersion: 0x%04x", pol.TPM12PolicyList.Version)
		log.Infof("\t\tReserved: % 02x", pol.TPM12PolicyList.Reserved)
		log.Infof("\t\tSignature Algorithm: 0x%02x", pol.TPM12PolicyList.SignaturAlg)
		log.Infof("\t\tEntries: %d bytes", pol.TPM12PolicyList.PolicyElementSize)

		for jdx, ent := range pol.TPM12PolicyList.PolicyElements {
			log.Infof("\t\tPolicy %d:", jdx)
			log.Infof("\t\t\tSize: %d bytes", ent.Size)
			log.Infof("\t\t\tType: %#v", ent.Type)
			log.Infof("\t\t\tPolicyEltControl: %#v", ent.PolicyEltControl)

			if ent.MLE != nil {
				log.Infof("\t\t\tSINITMinVersion: %d", ent.MLE.SINITMinVersion)
				log.Infof("\t\t\tHashAlg: 0x%04x", ent.MLE.HashAlg)
				log.Infof("\t\t\tNumHashes: %d", ent.MLE.NumHashes)

				for kdx, h := range ent.MLE.Hashes {
					log.Infof("\t\t\tHash %2d: %02x", kdx, h)
				}
			} else if ent.SBIOS != nil {
				log.Infof("\t\t\tHashAlg: 0x%04x", ent.SBIOS.HashAlg)
				log.Infof("\t\t\tReserved1: % 02x", ent.SBIOS.Reserved1)
				log.Infof("\t\t\tFallbackHash: %s", ent.SBIOS.FallbackHash.PrettyPrint())
				log.Infof("\t\t\tReserved2: % 02x", ent.SBIOS.Reserved2)
				log.Infof("\t\t\tNumHashes: %d", ent.SBIOS.NumHashes)

				for kdx, h := range ent.SBIOS.Hashes {
					log.Infof("\t\t\tHash %2d: %s", kdx, h.PrettyPrint())
				}
			} else if ent.PCONF != nil {
				log.Infof("\t\t\tNumPCRInfos: %d", ent.PCONF.NumPCRInfos)

				for kdx, info := range ent.PCONF.PCRInfos {
					log.Infof("\t\t\tPCR Info %d:", kdx)
					log.Infof("\t\t\t\tPCR Select: %v", info.PCRSelect)
					log.Infof("\t\t\t\tLocality: %d", info.LocalityAtRelease)
					log.Infof("\t\t\t\tDigest: %02x", info.DigestAtRelease)
				}
			} else if ent.Custom != nil {
				log.Infof("\t\t\tUUID: %08x-%04x-%04x-%04x-%02x", ent.Custom.UUID.data1, ent.Custom.UUID.data2, ent.Custom.UUID.data3, ent.Custom.UUID.data4, ent.Custom.UUID.data5)
				log.Infof("\t\t\tData: %02x", ent.Custom.Data)
			} else {
				log.Infof("\t\t\tError: Unknown Policy Element type")
			}
		}

		if pol.TPM12PolicyList.Signature != nil {
			log.Infof("\t\tSignature:")
			log.Infof("\t\t\tRevocation Counter: %#v", pol.TPM12PolicyList.Signature.RevocationCounter)
			log.Infof("\t\t\tPubkey Size: %d", pol.TPM12PolicyList.Signature.PubkeySize)
			log.Infof("\t\t\tPubkey Value: %02x", pol.TPM12PolicyList.Signature.PubkeyValue)
			log.Infof("\t\t\tSig Block: %02x", pol.TPM12PolicyList.Signature.SigBlock)
		} else {
			log.Infof("\t\tSignature: (None)")
		}
	}
}

// GenLCPPolicyV2 generates a LCPPolicyV2 structure with given hash algorithm
func GenLCPPolicyV2(version uint16, hashAlg crypto.Hash, hash []byte, sinitmin uint8, pc PolicyControl,
	apprHashes ApprovedHashAlgorithm, apprSigs ApprovedSignatureAlogrithm,
) (*LCPPolicy2, error) {
	var v uint16
	h, a := HashAlgMap[hashAlg]
	if !a {
		return nil, fmt.Errorf("invalid hash algorithm")
	}
	lcph, err := genLCPHash(hashAlg, hash)
	if err != nil {
		return nil, err
	}
	if version <= LCPPolicyVersion3 {
		v = LCPPolicyVersion3
	} else {
		v = version
	}
	apprH := deconstructApprovedHashAlgs(apprHashes)
	apprS := deconstructApprovedSigAlgs(apprSigs)
	p := deconstructPolicyControl(pc)
	pol := &LCPPolicy2{
		Version:                v,
		HashAlg:                h,
		PolicyType:             LCPPolicyTypeAny,
		SINITMinVersion:        sinitmin,
		DataRevocationCounters: [8]uint16{},
		PolicyControl:          p,
		MaxSINITMinVersion:     uint8(0),
		Reserved:               uint8(0),
		LcpHashAlgMask:         apprH,
		LcpSignAlgMask:         apprS,
	}
	copy(pol.PolicyHash[:], *lcph)
	return pol, nil
}

func deconstructPolicyControl(pc PolicyControl) uint32 {
	p := uint32(0)
	if pc.NPW {
		p += LCPPolicyControlNPW
	}
	if pc.SinitCaps {
		p += LCPPolicyControlSinitCaps
	}
	if pc.OwnerEnforced {
		p += LCPPolicyControlOwnerEnforced
	}
	if pc.AuxDelete {
		p += LCPPolicyControlAuxDelete
	}
	return p
}

func deconstructApprovedSigAlgs(apprSigs ApprovedSignatureAlogrithm) LCPPol2Sig {
	appr := LCPPol2Sig(0)
	if apprSigs.RSA2048SHA1 {
		appr += RSA2048SHA1
	}
	if apprSigs.RSA2048SHA256 {
		appr += RSA2048SHA256
	}
	if apprSigs.RSA3072SHA256 {
		appr += RSA3072SHA256
	}
	if apprSigs.RSA3072SHA384 {
		appr += RSA3072SHA384
	}
	if apprSigs.ECDSAP256SHA256 {
		appr += ECDSAP256SHA256
	}
	if apprSigs.ECDSAP384SHA384 {
		appr += ECDSAP384SHA384
	}
	if apprSigs.SM2SM2CurveSM3 {
		appr += SM2SM2CurveSM3
	}
	return appr
}

func deconstructApprovedHashAlgs(apprHashes ApprovedHashAlgorithm) uint16 {
	var appr uint16
	if apprHashes.SHA1 {
		appr = uint16(0x0001)
	}
	if apprHashes.SHA256 {
		appr = appr + uint16(0x0008)
	}
	if apprHashes.SHA384 {
		appr = appr + uint16(0x0040)
	}
	if apprHashes.SM3 {
		appr = appr + uint16(0x0020)
	}
	return appr
}

func genLCPHash(alg crypto.Hash, hash []byte) (*[]byte, error) {
	var ret []byte
	r := bytes.NewReader(hash)
	hByte := make([]byte, alg.Size())
	err := binary.Read(r, binary.LittleEndian, &hByte)
	if err != nil {
		return nil, err
	}
	copy(ret[:], hByte[:alg.Size()])
	return &ret, nil
}

// PrintPolicyControl can print PolicyControl field
func PrintPolicyControl(pc uint32) string {
	var b strings.Builder
	if (1 >> (pc & LCPPolicyControlNPW)) == 0 {
		b.WriteString("NPW + ")
	}
	if (1 >> (pc & LCPPolicyControlSinitCaps)) == 0 {
		b.WriteString("SinitCaps + ")
	}
	if (1 >> (pc & LCPPolicyControlOwnerEnforced)) == 0 {
		b.WriteString("OwnerEnforced + ")
	}
	if (1 >> (pc & LCPPolicyControlAuxDelete)) == 0 {
		b.WriteString("AuxDelete")
	}
	ret := strings.TrimSuffix(b.String(), " +")
	return ret
}

// PrettyPrint prints LCPPolicy2 Structure i a human readable format
func (p *LCPPolicy2) PrettyPrint() {
	var s strings.Builder
	s.WriteString("   Version: 0x" + strconv.FormatInt(int64(p.Version), 16) + "\n")
	s.WriteString("   HashAlg: " + p.HashAlg.String() + "\n")
	s.WriteString("   PolicyType: " + p.PolicyType.String() + "\n")
	s.WriteString("   SINITMinVersion: " + strconv.Itoa(int(p.SINITMinVersion)) + "\n")
	s.WriteString("   DataRevocationCounters: ")
	for _, item := range p.DataRevocationCounters {
		if item != 0 {
			s.WriteString(fmt.Sprintf("%v", item) + "+")
		}
	}
	s.WriteString("\n")
	s.WriteString("   PolicyControl: " + PrintPolicyControl(p.PolicyControl) + "\n")
	s.WriteString("   MaxSINITMinVersion: " + string(strconv.FormatInt(int64(p.MaxSINITMinVersion), 16)) + "\n")
	s.WriteString("   LcpHashAlgMask: " + PrintLcpHashAlgMask(p.LcpHashAlgMask) + "\n")
	s.WriteString("   LcpSignAlgMask: " + p.LcpSignAlgMask.String() + "\n")
	s.WriteString("   PolicyHash: " + fmt.Sprintf("%v", p.PolicyHash) + "\n")
	log.Infof("%s", s.String())
	log.Infoln()
}

// PrintLcpHashAlgMask prints LcpHashAlgMask in human readable format
func PrintLcpHashAlgMask(mask uint16) string {
	var b strings.Builder
	if (1 >> (mask & 0x0001)) == 0 {
		b.WriteString("SHA1 + ")
	}
	if (1 >> (mask & 0x0008)) == 0 {
		b.WriteString("SHA256 + ")
	}
	if (1 >> (mask & 0x0020)) == 0 {
		b.WriteString("SM3 + ")
	}
	if (1 >> (mask & 0x0040)) == 0 {
		b.WriteString("SHA385")
	}
	ret := strings.TrimSuffix(b.String(), " + ")
	return ret
}
