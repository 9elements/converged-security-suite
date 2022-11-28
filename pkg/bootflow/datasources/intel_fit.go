package datasources

import (
	"fmt"

	"github.com/9elements/converged-security-suite/v2/pkg/bootflow/systemartifacts/biosimage"
	"github.com/9elements/converged-security-suite/v2/pkg/bootflow/types"
	pkgbytes "github.com/linuxboot/fiano/pkg/bytes"
	"github.com/linuxboot/fiano/pkg/intel/metadata/fit"
)

type IntelFITFirst fit.EntryType

var _ types.DataSource = (IntelFITFirst)(0)

func (d IntelFITFirst) Data(state *types.State) (*types.Data, error) {
	biosFW, err := biosimage.Get(state)
	if err != nil {
		return nil, fmt.Errorf("unable to get BIOS image: %w", err)
	}
	fitEntries, err := fit.GetEntries(biosFW.Content)
	if err != nil {
		return nil, fmt.Errorf("unable to parse FIT table: %w", err)
	}

	for _, fitEntry := range fitEntries {
		if fitEntry.GetEntryBase().Headers.Type() == fit.EntryType(d) {
			offset := fitEntry.GetEntryBase().Headers.Address.Offset(uint64(len(biosFW.Content)))
			length := fitEntry.GetEntryBase().Headers.Size.Uint32()
			data := &types.Data{
				References: []types.Reference{{
					Artifact: biosFW,
					Ranges: pkgbytes.Ranges{{
						Offset: offset,
						Length: uint64(length),
					}},
				}},
			}
			return data, nil
		}
	}

	return nil, fmt.Errorf("unable to find FIT entry of type %s", fit.EntryType(d))
}

func (d IntelFITFirst) String() string {
	return fmt.Sprintf("IntelFITFirst(%s)", fit.EntryType(d))
}
