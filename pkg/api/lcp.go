package api

import (
	"bytes"
	"encoding/binary"
	"log"
)

const (
	LCPMaxLists      uint = 8
	SHA1DigestSize   uint = 20
	SHA256DigestSize uint = 32
	SHA384DigestSize uint = 48
	SHA512DigestSize uint = 64
	SM3DigestSize    uint = 32
)

type LCPPolicyHash struct {
	sha1   [SHA1DigestSize]uint8
	sha256 [SHA256DigestSize]uint8
	sha384 [SHA384DigestSize]uint8
	sha512 [SHA512DigestSize]uint8
	sm3    [SM3DigestSize]uint8
}

type LCPPolicyElement struct {
	Size             uint32
	Type             uint32
	PolicyEltControl uint32
	Data             []uint8
}

type LCPPolicyList2 struct {
	Version           uint16
	SignaturAlg       uint16
	PolicyElementSize uint32
	PolicyElements    []LCPPolicyElement
}

type LCPPolicyList struct {
	Version           uint16
	Reserved          uint8
	SignaturAlg       uint8
	PolicyElementSize uint32
	PolicyElements    []LCPPolicyElement
}

type LCPList struct {
	TPM12PolicyList LCPPolicyList
	//TPM20PolicyList LCPPolicyList2
}

type LCPPolicy struct {
	Version                uint16
	HashAlg                uint16
	PolicyType             uint8
	SINITMinVersion        uint8
	DataRevocationCounters [LCPMaxLists]uint16
	PolicyControl          uint32
	MaxSINITMinVersion     uint8
	MaxBIOSACMinVersion    uint8
	LCPHashAlgMask         uint16
	LCPSignaturAlgMask     uint32
	AUXHashAlgMask         uint16
	Reserved2              uint16
	//PolicyHash             LCPPolicyHash
}

type LCPPolicyData struct {
	FileSignature [32]int8
	Reserved      [3]uint8
	NumLists      uint8
	PolicyLists   []LCPList
}

func ParsePolicy(policy []byte) (*LCPPolicy, error) {
	var pol LCPPolicy

	buf := bytes.NewReader(policy)
	err := binary.Read(buf, binary.LittleEndian, &pol)
	if err != nil {
		return nil, err
	}

	return &pol, nil
}

func parsePolicyElement(buf *bytes.Reader, element *LCPPolicyElement) error {
	err := binary.Read(buf, binary.LittleEndian,
		element.Size)
	if err != nil {
		return err
	}
	err = binary.Read(buf, binary.LittleEndian,
		element.Type)
	if err != nil {
		return err
	}
	err = binary.Read(buf, binary.LittleEndian,
		element.PolicyEltControl)
	if err != nil {
		return err
	}
	element.Data = make([]uint8, element.Size)
	err = binary.Read(buf, binary.LittleEndian,
		element.Data)
	if err != nil {
		return err
	}

	return nil
}

func parsePolicyList(buf *bytes.Reader, list *LCPPolicyList) error {
	err := binary.Read(buf, binary.LittleEndian,
		list.Version)
	if err != nil {
		return err
	}

	log.Println("ffo")

	err = binary.Read(buf, binary.LittleEndian,
		list.Reserved)
	if err != nil {
		return err
	}

	err = binary.Read(buf, binary.LittleEndian,
		list.SignaturAlg)
	if err != nil {
		return err
	}

	err = binary.Read(buf, binary.LittleEndian,
		list.PolicyElementSize)
	if err != nil {
		return err
	}

	for i := 0; i < int(list.PolicyElementSize); i++ {
		parsePolicyElement(buf, &list.PolicyElements[i])
	}

	return nil
}

func parsePolicyList2(buf *bytes.Reader, list *LCPPolicyList2) error {
	err := binary.Read(buf, binary.LittleEndian,
		list.Version)
	if err != nil {
		return err
	}

	err = binary.Read(buf, binary.LittleEndian,
		list.SignaturAlg)
	if err != nil {
		return err
	}

	err = binary.Read(buf, binary.LittleEndian,
		list.PolicyElementSize)
	if err != nil {
		return err
	}

	for i := 0; i < int(list.PolicyElementSize); i++ {
		parsePolicyElement(buf, &list.PolicyElements[i])
	}

	return nil
}

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

	for i := 0; i < int(polData.NumLists); i++ {
		err = parsePolicyList(buf, &polData.PolicyLists[i].TPM12PolicyList)
		if err != nil {
			return nil, err
		}
	}

	return &polData, nil
}

func (p *LCPPolicy) PrettyPrint() {
	log.Printf("0x%02x\n", p.HashAlg)
}

func (pd *LCPPolicyData) PrettyPrint() {
	log.Println(pd)
}
