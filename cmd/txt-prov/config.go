package main

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"strconv"
	"strings"

	txt "github.com/9elements/converged-security-suite/v2/pkg/provisioning/txt"
	"github.com/9elements/converged-security-suite/v2/pkg/tools"
)

const (
	reservedDefault           = 0xff
	reserved2Default          = 0x0008
	sinitMinVersionDefault    = 0x0
	maxSinitMinVersionDefault = 0xff
)

type configJSON struct {
	Version            string `json:"Version"`            // Version field, 0x300 to 0x306 valid. If not set, 0x300 as default. Hex value
	HashAlg            string `json:"HashAlg"`            // Used has algorithm. Only one is valid. SHA1,SHA256,SHA384 supported
	PolicyType         string `json:"PolicyType"`         // Policytype 1 = Any, 0 = List
	SINITMinVersion    string `json:"SINITMinVersion"`    // SINITMinVersion. If not set, 0x0 as default. Hex value
	MaxSINITMinVersion string `json:"MaxSINITMinVersion"` // MaxSINITMinVersion. If not set, 0xff as default. Hex value
	PolicyControl      string `json:"PolicyControl"`      // List PolicyControl by name, separated by comma. NPW, OwnerEnforced,AuxDelete,SinitCaps
	LcpHashAlgMask     string `json:"LCPHashAlgMask"`     // List HashAlgs for LcpHashAlgMask, separated by comma. SHA1,SHA256,SHA384 supported
	LcpSignAlgMask     string `json:"LCPSignAlgMask"`     // List signing algorithms for LcpSignAlgMask, separated by comma. RSA2048SHA1,RSA2048SHA256,RSA3072SHA256,RSA3072SHA384,ECDSAP256SHA256,ECDSAP384SHA384 supported
}

func loadConfig(filename string) (*tools.LCPPolicy2, error) {
	var ok bool
	var b []byte
	var config configJSON
	b, err := ioutil.ReadFile(filename)
	if err != nil {
		return nil, err
	}
	if err := json.Unmarshal(b, &config); err != nil {
		return nil, err
	}
	ver, err := strconv.ParseUint(config.Version, 16, 0)
	if err != nil {
		return nil, err
	}
	if uint16(ver) < uint16(0x300) || uint16(ver) > uint16(0x306) {
		return nil, fmt.Errorf("Invalid LCP Version. Want: 0x300 - 0x306 - Have: %v", config.Version)
	}
	hashAlg, ok := tools.HashAlgMap[txt.HashMapping[config.HashAlg]]
	if ok == false {
		return nil, fmt.Errorf("Cant determin hash algorithm")
	}
	var pT int
	if config.PolicyType == "Any" {
		pT = 1
	} else if config.PolicyType == "List" {
		pT = 0
	} else {
		return nil, fmt.Errorf("Invalid PolicyType. Want: List (Signed Policy) or Any (Auto promotion) - Have: %v", config.PolicyType)
	}
	var smv, msmv uint64
	if len(config.SINITMinVersion) > 0 {
		smv, err = strconv.ParseUint(config.SINITMinVersion, 16, 0)
		if err != nil {
			return nil, err
		}
	} else {
		smv = sinitMinVersionDefault
	}
	if len(config.MaxSINITMinVersion) > 0 {
		msmv, err = strconv.ParseUint(config.MaxSINITMinVersion, 16, 0)
		if err != nil {
			return nil, err
		}
	} else {
		msmv = maxSinitMinVersionDefault
	}
	s1 := strings.Split(config.LcpSignAlgMask, ",")
	var s1val tools.LCPPol2Sig
	for _, item := range s1 {
		s1val += tools.SignMaskMap[item]
	}

	s2 := strings.Split(config.LcpHashAlgMask, ",")
	var s2val uint16
	for _, item := range s2 {
		s2val += tools.HashMaskMap[item]
	}
	s3 := strings.Split(config.PolicyControl, ",")
	var s3val uint32
	for _, item := range s3 {
		s3val += tools.PolicyControlMap[item]
	}
	// Fixed SHA256 use
	var hash [32]byte
	for iterator := range hash {
		hash[iterator] = byte(iterator)
	}
	lcppol := tools.LCPPolicy2{
		Version:                uint16(ver),
		HashAlg:                hashAlg,
		PolicyType:             tools.LCPPolicyType(pT),
		SINITMinVersion:        uint8(smv),
		DataRevocationCounters: [8]uint16{0, 0, 0, 0, 0, 0, 0, 0},
		PolicyControl:          s3val,
		MaxSINITMinVersion:     uint8(msmv),
		Reserved:               uint8(reservedDefault),
		LcpHashAlgMask:         s2val,
		LcpSignAlgMask:         s1val,
		Reserved2:              uint32(reserved2Default),
		PolicyHash:             hash,
	}
	return &lcppol, nil
}
