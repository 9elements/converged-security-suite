package amdconds

import (
	"github.com/9elements/converged-security-suite/v2/pkg/bootflow/systemartifacts/biosimage"
	"github.com/9elements/converged-security-suite/v2/pkg/bootflow/types"
	"github.com/linuxboot/fiano/pkg/amd/manifest"
)

// ManifestPresent checks if AMD metadata structures as present.
type ManifestPresent struct{}

var _ types.Condition = (*ManifestPresent)(nil)

// Check implements types.Condition.
func (ManifestPresent) Check(s *types.State) bool {
	biosImg, err := biosimage.Get(s)
	if err != nil {
		return false
	}

	uefi, _ := biosImg.Parse()
	if uefi == nil {
		return false
	}

	fw, _ := manifest.NewAMDFirmware(uefi)
	return fw != nil
}
