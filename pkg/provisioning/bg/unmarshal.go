package bg

import (
	"errors"
	"io"

	"github.com/9elements/converged-security-suite/v2/pkg/intel/metadata/manifest/bootpolicy"
	"github.com/9elements/converged-security-suite/v2/pkg/intel/metadata/manifest/key"
)

// ParseBPM reads from a binary and parses into the boot policy manifest structure
func ParseBPM(reader io.Reader) (*bootpolicy.Manifest, error) {
	bpm := &bootpolicy.Manifest{}
	_, err := bpm.ReadFrom(reader)
	if err != nil && !errors.Is(err, io.EOF) {
		return nil, err
	}
	return bpm, nil
}

// ParseKM reads from a binary source and parses into the key manifest structure
func ParseKM(reader io.Reader) (*key.Manifest, error) {
	km := &key.Manifest{}
	_, err := km.ReadFrom(reader)
	if err != nil && !errors.Is(err, io.EOF) {
		return nil, err
	}
	return km, nil
}
