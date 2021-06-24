package pcr

import (
	"fmt"

	"github.com/9elements/converged-security-suite/v2/pkg/intel/metadata/fit"
)

// ValidateManifests validates if boot policy manifest (BPM) and key
// manifest (KM) are correct.
type ValidateManifests struct{}

// Validate implements Validator.
func (v ValidateManifests) Validate(firmware Firmware) error {
	fitEntries, err := fit.GetEntries(firmware.Buf())
	if err != nil {
		return fmt.Errorf("unable to parse FIT entries: %w", err)
	}

	km, kmFIT, err := getKeyManifest(fitEntries)
	if err != nil {
		return fmt.Errorf("unable to get Key Manifest: %w", err)
	}

	if err := km.KeyAndSignature.Verify(kmFIT.DataBytes[:km.KeyManifestSignatureOffset]); err != nil {
		return fmt.Errorf("unable to confirm KM signature: %w", err)
	}

	bpm, bpmFIT, err := getBootPolicyManifest(fitEntries)
	if err != nil {
		return fmt.Errorf("unable to get Boot Policy Manifest: %w", err)
	}

	if err := bpm.PMSE.KeySignature.Verify(bpmFIT.DataBytes[:bpm.KeySignatureOffset]); err != nil {
		return fmt.Errorf("unable to confirm KM signature: %w", err)
	}

	if err := km.ValidateBPMKey(bpm.PMSE.KeySignature); err != nil {
		return fmt.Errorf("key chain is invalid: %w", err)
	}

	if err := bpm.ValidateIBBs(firmware); err != nil {
		return fmt.Errorf("IBB signature in BPM is not valid: %w", err)
	}

	return nil
}
