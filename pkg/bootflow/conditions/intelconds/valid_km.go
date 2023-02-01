package intelconds

import (
	"fmt"

	"github.com/9elements/converged-security-suite/v2/pkg/bootflow/systemartifacts/biosimage/accessor/intelbiosimage"
	"github.com/9elements/converged-security-suite/v2/pkg/bootflow/types"
	key "github.com/linuxboot/fiano/pkg/intel/metadata/cbnt/cbntkey"
	"github.com/linuxboot/fiano/pkg/intel/metadata/fit"
)

type ValidKM struct{}

func (ValidKM) Check(s *types.State) bool {
	intelFW, err := intelbiosimage.Get(s)
	if err != nil {
		return false
	}

	km, kmFIT, err := intelFW.KeyManifest()
	if err != nil {
		return false
	}

	return validateKM(km, kmFIT) == nil
}

// TODO: move this to linuxboot/fiano
func validateKM(
	km *key.Manifest,
	kmFIT *fit.EntryKeyManifestRecord,
) error {
	if err := km.KeyAndSignature.Verify(kmFIT.DataSegmentBytes[:km.KeyManifestSignatureOffset]); err != nil {
		return fmt.Errorf("unable to confirm KM signature: %w", err)
	}

	return nil
}
