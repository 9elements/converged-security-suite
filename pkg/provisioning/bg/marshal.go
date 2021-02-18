package bg

import (
	"bytes"
	"crypto"
	"crypto/x509"
	"encoding/pem"
	"fmt"

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
