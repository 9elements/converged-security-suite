package txt

import (
	"crypto"

	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpmutil"
)

const (
	tpm2PSNVIndex    = 0x01C10103
	tpm2AUXNVIndex   = 0x01C10102
	tpm2PSIndexSize  = 70
	tpm2AUXIndexSize = 104
)

var (
	// AUX Index Hash Data
	tpm20AUXIndexHashData = tpmutil.U16Bytes{0xEF, 0x9A, 0x26, 0xFC, 0x22, 0xD1, 0xAE, 0x8C, 0xEC, 0xFF, 0x59, 0xE9, 0x48, 0x1A, 0xC1, 0xEC, 0x53, 0x3D, 0xBE, 0x22, 0x8B, 0xEC, 0x6D, 0x17, 0x93, 0x0F, 0x4C, 0xB2, 0xCC, 0x5B, 0x97, 0x24}

	tpm2PSIndexDef = tpm2.NVPublic{
		NVIndex: tpmutil.Handle(tpm2PSNVIndex),
		NameAlg: tpm2.AlgSHA256,
		Attributes: tpm2.AttrPolicyWrite + tpm2.AttrPolicyDelete +
			tpm2.AttrAuthRead + tpm2.AttrNoDA + tpm2.AttrPlatformCreate,
		DataSize: uint16(tpm2PSIndexSize),
	}

	tpm20AUXIndexDef = tpm2.NVPublic{
		NVIndex: tpmutil.Handle(tpm2AUXNVIndex),
		NameAlg: tpm2.AlgSHA256,
		Attributes: tpm2.AttrPolicyWrite + tpm2.AttrPolicyDelete +
			tpm2.AttrWriteSTClear + tpm2.AttrAuthRead + tpm2.AttrNoDA + tpm2.AttrPlatformCreate,
		AuthPolicy: tpm20AUXIndexHashData,
		DataSize:   uint16(tpm2AUXIndexSize),
	}
)

// HashMapping exports a map to convert hash names to its respective library object.
var HashMapping = map[string]crypto.Hash{
	"SHA1":   crypto.SHA1,
	"SHA256": crypto.SHA256,
	"SHA384": crypto.SHA384,
	"SHA512": crypto.SHA512,
}
