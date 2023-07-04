package inteldata

import (
	"context"
	"encoding/binary"
	"fmt"

	"github.com/9elements/converged-security-suite/v2/pkg/bootflow/systemartifacts/biosimage"
	"github.com/9elements/converged-security-suite/v2/pkg/bootflow/types"
	"github.com/facebookincubator/go-belt/tool/logger"
	"github.com/hashicorp/go-multierror"
	pkgbytes "github.com/linuxboot/fiano/pkg/bytes"
	"github.com/linuxboot/fiano/pkg/intel/metadata/fit"
)

// ACMDate implements DataSource by referencing to the ACM date value.
type ACMDate struct{}

var _ types.DataSource = (*ACMDate)(nil)

// Data implements types.DataSource.
func (ACMDate) Data(ctx context.Context, state *types.State) (*types.Data, error) {
	biosFW, err := biosimage.Get(state)
	if err != nil {
		return nil, fmt.Errorf("unable to get BIOS image: %w", err)
	}
	fitEntries, err := fit.GetEntries(biosFW.Content)
	if err != nil {
		return nil, fmt.Errorf("unable to parse FIT table: %w", err)
	}

	var errors *multierror.Error
	found := false
	ref := types.Reference{
		Artifact: biosFW,
		MappedRanges: types.MappedRanges{
			AddressMapper: biosimage.PhysMemMapper{},
			Ranges:        []pkgbytes.Range{},
		},
	}
	result := types.NewData(&ref)
	for _, fitEntry := range fitEntries {
		switch fitEntry := fitEntry.(type) {
		case *fit.EntrySACM: // startup AC module entry
			found = true

			errors = multierror.Append(errors, fitEntry.HeadersErrors...)
			data, err := fitEntry.ParseData()
			if err != nil {
				errors = multierror.Append(errors, err)
			}
			if data == nil {
				continue
			}

			sacmPointer := fitEntry.Headers.Address.Pointer()
			offset := sacmPointer + uint64(data.DateBinaryOffset())
			length := uint64(binary.Size(data.GetDate()))

			ref.Ranges = append(ref.Ranges, pkgbytes.Range{
				Offset: offset,
				Length: length,
			})
		}
	}

	if !found {
		if errors != nil {
			return nil, errors
		}
		return nil, fmt.Errorf("ACM was not found")
	}

	if errors != nil {
		logger.Debugf(ctx, "errors: %v", errors.Error())
	}

	return result, nil
}

// String implements fmt.Stringer.
func (ACMDate) String() string {
	return "ACMDate"
}
