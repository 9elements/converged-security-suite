package datasources

import (
	"context"
	"fmt"
	"strings"

	"github.com/9elements/converged-security-suite/v2/pkg/bootflow/types"
	"github.com/9elements/converged-security-suite/v2/pkg/uefi/ffs"
	"github.com/linuxboot/fiano/pkg/uefi"
)

type UEFIFilesByName []string

var _ types.DataSource = (UEFIFilesByName)(nil)

// Data implements types.DataSource.
func (ds UEFIFilesByName) Data(ctx context.Context, state *types.State) (*types.Data, error) {
	return UEFIFiles(func(f *uefi.File) (bool, error) {
		var fileNamePtr *string
		visitor := &ffs.NodeVisitor{
			Callback: func(node ffs.Node) (bool, error) {
				if _, ok := node.Firmware.(*uefi.FirmwareVolume); ok {
					return false, nil
				}
				section, ok := node.Firmware.(*uefi.Section)
				if !ok {
					return true, nil
				}
				if section.Header.Type != uefi.SectionTypeUserInterface {
					return true, nil
				}

				fileNamePtr = &section.Name
				return false, nil
			},
			FallbackToContainerRange: true,
		}
		if err := visitor.Run(f); err != nil {
			return false, fmt.Errorf("unable to traverse the file layout: %w", err)
		}

		if fileNamePtr == nil {
			return false, nil
		}
		fileName := *fileNamePtr

		for _, fn := range ds {
			if fn == fileName {
				return true, nil
			}
		}
		return false, nil
	}).Data(ctx, state)
}

func (ds UEFIFilesByName) fileNamesString() string {
	return strings.Join([]string(ds), ", ")
}

// String implements fmt.Stringer.
func (ds UEFIFilesByName) String() string {
	return fmt.Sprintf("UEFIFilesByName(%s)", ds.fileNamesString())
}
