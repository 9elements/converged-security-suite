package validator

import (
	"context"
	"fmt"

	"github.com/9elements/converged-security-suite/v2/pkg/bootflow/bootengine"
	"github.com/9elements/converged-security-suite/v2/pkg/bootflow/datasources"
	"github.com/9elements/converged-security-suite/v2/pkg/bootflow/lib/format"
	"github.com/9elements/converged-security-suite/v2/pkg/bootflow/types"
	"github.com/linuxboot/fiano/pkg/uefi"
)

// ValidatorFinalCoverageIsComplete check if all PE32 files are protected.
type ValidatorFinalCoverageIsComplete struct{}

var _ Validator = (*ValidatorFinalCoverageIsComplete)(nil)

// Validate implements Validator.
func (ValidatorFinalCoverageIsComplete) Validate(
	ctx context.Context,
	s *types.State,
	l bootengine.Log,
) Issues {
	if len(l) == 0 {
		return nil
	}

	var measured types.References
	for _, step := range l {
		measured = append(measured, step.MeasuredData.References()...)
		measured.SortAndMerge()
	}

	data, err := datasources.UEFIFiles(func(f *uefi.File) (bool, error) {
		for _, section := range f.Sections {
			switch section.Header.Type {
			case uefi.SectionTypePE32, uefi.SectionTypePIC, uefi.SectionTypeTE:
				return true, nil
			}
		}
		return false, nil
	}).Data(ctx, s)
	if err != nil {
		return Issues{{
			StepIdx: uint(len(l) - 1),
			StepIssue: bootengine.StepIssue{
				Coords: nil,
				Issue:  fmt.Errorf("unable to get UEFI files: %w", err),
			},
		}}
	}

	nonMeasured := data.References().Exclude(measured...)
	if len(nonMeasured) == 0 {
		return nil
	}
	_ = measured.Resolve()
	_ = nonMeasured.Resolve()
	return Issues{{
		StepIdx: uint(len(l) - 1),
		StepIssue: bootengine.StepIssue{
			Coords: nil,
			Issue: fmt.Errorf(
				"executable areas %s are not protected; protected areas are only: %s",
				format.NiceString(nonMeasured),
				format.NiceString(measured),
			),
		},
	}}
}
