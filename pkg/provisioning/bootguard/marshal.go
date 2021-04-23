package bootguard

import (
	"bytes"
	"crypto"

	"github.com/9elements/converged-security-suite/v2/pkg/provisioning/bootguard/common"

	"github.com/9elements/converged-security-suite/v2/pkg/provisioning/bootguard/bootpolicy"
	"github.com/9elements/converged-security-suite/v2/pkg/provisioning/bootguard/key"
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
	if err := km.KeyAndSignature.FillSignature(0, pubKey, signature, common.AlgSHA256); err != nil {
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
	bpm.PMSE = *bootpolicy.NewSignature()

	if err := bpm.PMSE.KeySignature.FillSignature(0, pubKey, signature, common.AlgNull); err != nil {
		return nil, err
	}

	bpm.RehashRecursive()
	if err := bpm.Validate(); err != nil {
		return nil, err
	}
	return WriteBPM(bpm)
}
