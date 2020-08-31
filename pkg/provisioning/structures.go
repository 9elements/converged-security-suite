package provisioning

import (
	"crypto"

	tss "github.com/9elements/go-tss"
	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpmutil"
)

var (
	// AUX Index Hash Data
	tpm20AUXIndexHashData = tpmutil.U16Bytes{0xEF, 0x9A, 0x26, 0xFC, 0x22, 0xD1, 0xAE, 0x8C, 0xEC, 0xFF, 0x59, 0xE9, 0x48, 0x1A, 0xC1, 0xEC, 0x53, 0x3D, 0xBE, 0x22, 0x8B, 0xEC, 0x6D, 0x17, 0x93, 0x0F, 0x4C, 0xB2, 0xCC, 0x5B, 0x97, 0x24}
	tpmCon                *tss.TPM

	tpm2PSIndexDef = tpm2.NVPublic{
		NVIndex: tpmutil.Handle(0x01C10103),
		Attributes: tpm2.AttrPolicyWrite + tpm2.AttrPolicyDelete +
			tpm2.AttrAuthRead + tpm2.AttrNoDA + tpm2.AttrPlatformCreate,
		DataSize: uint16(70),
	}

	tpm20AUXIndexDef = tpm2.NVPublic{
		NVIndex: tpmutil.Handle(0x01C10102),
		NameAlg: tpm2.AlgSHA256,
		Attributes: tpm2.AttrPolicyWrite + tpm2.AttrPolicyDelete +
			tpm2.AttrWriteSTClear + tpm2.AttrAuthRead + tpm2.AttrNoDA + tpm2.AttrPlatformCreate,
		AuthPolicy: tpm20AUXIndexHashData,
		DataSize:   uint16(104),
	}
)

// HashMapping exports a map to convert hash names to its respective library object.
var HashMapping = map[string]crypto.Hash{
	"SHA1":   crypto.SHA1,
	"SHA256": crypto.SHA256,
	"SHA384": crypto.SHA384,
	"SHA512": crypto.SHA512,
}

// LCP2ConfigJSON exports for parsing Provisioning information.
type LCP2ConfigJSON struct {
	Version         string `json:"Version"`         // Version field, 0x300 to 0x306 valid. If not set, 0x302 as default
	HashAlg         string `json:"HashAlg"`         // Used has algorithm. Only one is valid. SHA1,SHA256,SHA384 supported
	PolicyType      string `json:"PolicyType"`      // Policytype 1 = Any, 0 = List
	SINITMinVersion string `json:"SINITMinVersion"` // SINITMinVersion
	PolicyControl   string `json:"PolicyControl"`   // List PolicyControl by name, separated by comma. NPW, OwnerEnforced,AuxDelete,SinitCaps
	LcpHashAlgMask  string `json:"LCPHashAlgMask"`  // List HashAlgs for LcpHashAlgMask, separated by comma. SHA1,SHA256,SHA384 supported
	LcpSignAlgMask  string `json:"LCPSignAlgMask"`  // List signing algorithms for LcpSignAlgMask, separated by comma. RSA2048SHA1,RSA2048SHA256,RSA3072SHA256,RSA3072SHA384,ECDSAP256SHA256,ECDSAP384SHA384 supported
}
