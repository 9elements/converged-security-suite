package intelconds

import (
	"fmt"

	"github.com/9elements/converged-security-suite/v2/pkg/bootflow/systemartifacts/biosimage"
	"github.com/9elements/converged-security-suite/v2/pkg/bootflow/systemartifacts/biosimage/accessor/intelbiosimage"
	"github.com/9elements/converged-security-suite/v2/pkg/bootflow/types"
	"github.com/linuxboot/fiano/pkg/intel/metadata/manifest/bootpolicy"
)

type ValidIBB struct{}

func (ValidIBB) Check(s *types.State) bool {
	intelFW, err := intelbiosimage.Get(s)
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
