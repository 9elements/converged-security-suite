package intelconds

import (
	"context"
	"fmt"

	"github.com/9elements/converged-security-suite/v2/pkg/bootflow/systemartifacts/biosimage/accessor/intelbiosimage"
	"github.com/9elements/converged-security-suite/v2/pkg/bootflow/types"
	bootpolicy "github.com/linuxboot/fiano/pkg/intel/metadata/cbnt/bootpolicy"
	key "github.com/linuxboot/fiano/pkg/intel/metadata/cbnt/keymanifest"
	"github.com/linuxboot/fiano/pkg/intel/metadata/fit"
)

// ValidBPM checks if the Intel Boot Policy Manifest is valid (including its signatures).
type ValidBPM struct{}

// Check implements types.Condition.
func (ValidBPM) Check(ctx context.Context, s *types.State) bool {
	intelFW, err := intelbiosimage.Get(ctx, s)
	if err != nil {
		return false
	}

	km, _, err := intelFW.KeyManifest()
	if err != nil {
		return false
	}

	bpm, bpmFIT, err := intelFW.BootPolicyManifest()
	if err != nil {
		return false
	}

	return validateBPM(*km, *bpm, bpmFIT) == nil
}

// TODO: move this to linuxboot/fiano
func validateBPM(
	km key.Manifest,
	bpm bootpolicy.Manifest,
	bpmFIT *fit.EntryBootPolicyManifestRecord,
) error {
	if err := bpm.Validate(); err != nil {
		return nil
	}

	if bpmBg, ok := bpm.(*bootpolicy.ManifestBG); ok {
		off, err := bpmBg.PMSE.OffsetOf(1)
		if err != nil {
			return err
		}

		if err := bpmBg.PMSE.Verify(bpmFIT.DataSegmentBytes[:off]); err != nil {
			return fmt.Errorf("unable to confirm KM signature: %w", err)
		}

		// It is safe to assume that in the normal conditions there won't be
		// mixed revisions of BPM and KM, otherwise we have bigger problems
		// than non-matching BPM key in KM...
		if err := km.(*key.BGManifest).ValidateBPMKey(bpmBg.PMSE.KeySignature); err != nil {
			return fmt.Errorf("key chain is invalid: %w", err)
		}
	}

	if bpmCBnt, ok := bpm.(*bootpolicy.ManifestCBnT); ok {
		off, err := bpmCBnt.PMSE.OffsetOf(1)
		if err != nil {
			return err
		}

		if err := bpmCBnt.PMSE.KeySignature.Verify(bpmFIT.DataSegmentBytes[:off]); err != nil {
			return fmt.Errorf("unable to confirm KM signature: %w", err)
		}

		// Same assumption as above.
		if err := km.(*key.BGManifest).ValidateBPMKey(bpmCBnt.PMSE.KeySignature); err != nil {
			return fmt.Errorf("key chain is invalid: %w", err)
		}
	}

	return nil
}
