package pcr

import (
	"fmt"

	"github.com/linuxboot/fiano/pkg/intel/metadata/fit"
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

	km1, km2, kmFIT, err := getKeyManifest(fitEntries)
	if err != nil {
		return fmt.Errorf("unable to get Key Manifest: %w", err)
	}
	if km1 != nil {
		// not supported, yet
		return nil
	}

	if err := km2.KeyAndSignature.Verify(kmFIT.DataSegmentBytes[:km2.KeyManifestSignatureOffset]); err != nil {
		return fmt.Errorf("unable to confirm KM signature: %w", err)
	}

	bpm1, bpm2, bpmFIT, err := getBootPolicyManifest(fitEntries)
	if err != nil {
		return fmt.Errorf("unable to get Boot Policy Manifest: %w", err)
	}
	if bpm1 != nil {
		// not supported, yet
		return nil
	}

	if err := bpm2.PMSE.KeySignature.Verify(bpmFIT.DataSegmentBytes[:bpm2.KeySignatureOffset]); err != nil {
		return fmt.Errorf("unable to confirm KM signature: %w", err)
	}

	if err := km2.ValidateBPMKey(bpm2.PMSE.KeySignature); err != nil {
		return fmt.Errorf("key chain is invalid: %w", err)
	}

	if err := bpm2.ValidateIBB(firmware); err != nil {
		return fmt.Errorf("IBB signature in BPM is not valid: %w", err)
	}

	return nil
}
