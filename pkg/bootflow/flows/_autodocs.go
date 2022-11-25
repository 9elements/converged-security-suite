//go:build none
// +build none

package flows

import (
	"github.com/9elements/converged-security-suite/v2/pkg/bootflow/steps/commonsteps"
	"github.com/9elements/converged-security-suite/v2/pkg/bootflow/steps/tpmsteps"
)

// This files is used only to provide hints to the "goplantuml" tool

type OCPDXE struct {
	commonsteps.SetActorPredefined
	tpmsteps.InitTPMLazy
	tpmsteps.MeasurePCD
	tpmsteps.MeasureUEFIGUIDFirst
	tpmsteps.MeasureSeparator
}
