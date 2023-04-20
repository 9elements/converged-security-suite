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

	kmV1, kmV2, kmFIT, err := getKeyManifest(fitEntries)
	if err != nil {
		return fmt.Errorf("unable to get Key Manifest: %w", err)
	}
	if kmV1 != nil {
		// not supported, yet
		return nil
	}

	if err := kmV2.KeyAndSignature.Verify(kmFIT.DataSegmentBytes[:kmV2.KeyManifestSignatureOffset]); err != nil {
		return fmt.Errorf("unable to confirm KM signature: %w", err)
	}

	bpmV1, bpmV2, bpmFIT, err := getBootPolicyManifest(fitEntries)
	if err != nil {
		return fmt.Errorf("unable to get Boot Policy Manifest: %w", err)
	}
	if bpmV1 != nil {
		// not supported, yet
		return nil
	}

	if err := bpmV2.PMSE.KeySignature.Verify(bpmFIT.DataSegmentBytes[:bpmV2.KeySignatureOffset]); err != nil {
		return fmt.Errorf("unable to confirm KM signature: %w", err)
	}

	if err := kmV2.ValidateBPMKey(bpmV2.PMSE.KeySignature); err != nil {
		return fmt.Errorf("key chain is invalid: %w", err)
	}

	if err := bpmV2.ValidateIBB(firmware); err != nil {
		return fmt.Errorf("IBB signature in BPM is not valid: %w", err)
	}

	return nil
}
