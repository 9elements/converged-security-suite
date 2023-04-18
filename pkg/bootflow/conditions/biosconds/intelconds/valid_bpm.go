package intelconds

import (
	"context"
	"fmt"

	"github.com/9elements/converged-security-suite/v2/pkg/bootflow/systemartifacts/biosimage/accessor/intelbiosimage"
	"github.com/9elements/converged-security-suite/v2/pkg/bootflow/types"
	bootpolicy "github.com/linuxboot/fiano/pkg/intel/metadata/cbnt/cbntbootpolicy"
	key "github.com/linuxboot/fiano/pkg/intel/metadata/cbnt/cbntkey"
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

	return validateBPM(km, bpm, bpmFIT) == nil
}

// TODO: move this to linuxboot/fiano
func validateBPM(
	km *key.Manifest,
	bpm *bootpolicy.Manifest,
	bpmFIT *fit.EntryBootPolicyManifestRecord,
) error {
	if err := bpm.Validate(); err != nil {
		return nil
	}

	if err := bpm.PMSE.KeySignature.Verify(bpmFIT.DataSegmentBytes[:bpm.KeySignatureOffset]); err != nil {
		return fmt.Errorf("unable to confirm KM signature: %w", err)
	}

	if err := km.ValidateBPMKey(bpm.PMSE.KeySignature); err != nil {
		return fmt.Errorf("key chain is invalid: %w", err)
	}

	return nil
}
