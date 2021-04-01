package cbnt

import (
	"bytes"
	"crypto"
	"crypto/x509"
	"encoding/pem"
	"fmt"

	"github.com/9elements/converged-security-suite/v2/pkg/intel/metadata/manifest"
	"github.com/9elements/converged-security-suite/v2/pkg/intel/metadata/manifest/bootpolicy"
	"github.com/9elements/converged-security-suite/v2/pkg/intel/metadata/manifest/key"
)

// WriteKM returns a key manifest as bytes in format defined in #575623.
func WriteKM(km *key.Manifest) ([]byte, error) {
	buf := new(bytes.Buffer)
	_, err := km.WriteTo(buf)
	return buf.Bytes(), err
}

// WriteBPM returns a boot policy manifest as byte slice
func WriteBPM(bpm *bootpolicy.Manifest) ([]byte, error) {
	buf := new(bytes.Buffer)
	_, err := bpm.WriteTo(buf)
	return buf.Bytes(), err
}

// StitchKM returns a key manifest manifest as byte slice
func StitchKM(km *key.Manifest, pubKey crypto.PublicKey, signature []byte) ([]byte, error) {
	if err := km.KeyAndSignature.FillSignature(0, pubKey, signature, km.PubKeyHashAlg); err != nil {
		return nil, err
	}
	km.RehashRecursive()
	if err := km.Validate(); err != nil {
		return nil, err
	}
	return WriteKM(km)
}

// StitchBPM returns a boot policy manifest as byte slice
func StitchBPM(bpm *bootpolicy.Manifest, pubKey crypto.PublicKey, signature []byte) ([]byte, error) {
	PMSEString := [8]byte{0x5f, 0x5f, 0x50, 0x4d, 0x53, 0x47, 0x5f, 0x5f}
	bpm.PMSE.StructInfo = bootpolicy.StructInfo{}
	bpm.PMSE.StructInfo.ID = PMSEString
	bpm.PMSE.StructInfo.Version = 0x20

	if err := bpm.PMSE.KeySignature.FillSignature(0, pubKey, signature, manifest.AlgNull); err != nil {
		return nil, err
	}

	bpm.RehashRecursive()
	if err := bpm.Validate(); err != nil {
		return nil, err
	}
	return WriteBPM(bpm)
}

func parsePrivateKey(raw []byte) (crypto.Signer, error) {
	for {
		block, rest := pem.Decode(raw)
		if block == nil {
			break
		}
		if block.Type != "CERTIFICATE" {
			key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
			if err == nil {
				if key, ok := key.(crypto.Signer); ok {
					return key, nil
				}
				return nil, fmt.Errorf("found unknown private key type (%T) in PKCS#8 wrapping", key)
			}
			return nil, err

		}
		raw = rest
	}
	return nil, fmt.Errorf("failed to parse private key")
}
