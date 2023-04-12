package intelconds

import (
	"context"
	"fmt"

	"github.com/9elements/converged-security-suite/v2/pkg/bootflow/systemartifacts/biosimage"
	"github.com/9elements/converged-security-suite/v2/pkg/bootflow/systemartifacts/biosimage/accessor/intelbiosimage"
	"github.com/9elements/converged-security-suite/v2/pkg/bootflow/types"
	bootpolicy "github.com/linuxboot/fiano/pkg/intel/metadata/cbnt/cbntbootpolicy"
)

// ValidIBB checks if the Initial Boot Block is valid (including its signatures).
type ValidIBB struct{}

// Check implements types.Condition.
func (ValidIBB) Check(ctx context.Context, s *types.State) bool {
	intelFW, err := intelbiosimage.Get(ctx, s)
	if err != nil {
		return false
	}

	bpm, _, err := intelFW.BootPolicyManifest()
	if err != nil {
		return false
	}

	return validateIBB(bpm, intelFW.SystemArtifact()) == nil
}

func validateIBB(
	bpm *bootpolicy.Manifest,
	img *biosimage.BIOSImage,
) error {
	uefi, err := img.Parse()
	if err != nil {
		return fmt.Errorf("unable to parse the UEFI layout: %w", err)
	}

	if err := bpm.ValidateIBB(uefi); err != nil {
		return fmt.Errorf("IBB signature in BPM is not valid: %w", err)
	}

	return nil
}
