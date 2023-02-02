package datasources

import (
	"context"
	"fmt"
	"strings"

	"github.com/9elements/converged-security-suite/v2/pkg/bootflow/types"
	"github.com/linuxboot/fiano/pkg/uefi"
)

// UEFIFilesByType implements types.DataSource by referencing to the files
// in the UEFI layout which has types from the given list.
type UEFIFilesByType []uefi.FVFileType

var _ types.DataSource = (UEFIFilesByType)(nil)

// Data implements types.DataSource.
func (ds UEFIFilesByType) Data(ctx context.Context, state *types.State) (*types.Data, error) {
	return UEFIFiles(func(f *uefi.File) (bool, error) {
		for _, ft := range ds {
			if f.Header.Type == ft {
				return true, nil
			}
		}
		return false, nil
	}).Data(ctx, state)
}

func (ds UEFIFilesByType) fileTypesString() string {
	var result []string
	for _, fileType := range ds {
		result = append(result, fileType.String())
	}
	return strings.Join(result, ", ")
}

// String implements fmt.Stringer.
func (ds UEFIFilesByType) String() string {
	return fmt.Sprintf("UEFIFilesByType(%s)", ds.fileTypesString())
}
