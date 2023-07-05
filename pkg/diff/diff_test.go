package diff

import (
	"testing"

	"github.com/9elements/converged-security-suite/v2/pkg/bootflow/systemartifacts/biosimage"
	"github.com/9elements/converged-security-suite/v2/pkg/bootflow/types"
	pkgbytes "github.com/linuxboot/fiano/pkg/bytes"
	"github.com/stretchr/testify/require"
)

type noMapper struct{}

var _ types.AddressMapper = noMapper{}

func (noMapper) Resolve(_ types.SystemArtifact, ranges ...pkgbytes.Range) (pkgbytes.Ranges, error) {
	return ranges, nil
}
func (noMapper) Unresolve(_ types.SystemArtifact, ranges ...pkgbytes.Range) (pkgbytes.Ranges, error) {
	return ranges, nil
}

func TestDiff(t *testing.T) {
	t.Run("arbitraryOrder", func(t *testing.T) {
		report, err := Diff(pkgbytes.Ranges{
			pkgbytes.Range{
				Offset: 3,
				Length: 1,
			},
			pkgbytes.Range{
				Offset: 1,
				Length: 0,
			},
			pkgbytes.Range{
				Offset: 2,
				Length: 1,
			},
			pkgbytes.Range{
				Offset: 2,
				Length: 1,
			},
			pkgbytes.Range{
				Offset: 0,
				Length: 1,
			},
		}, noMapper{}, biosimage.New([]byte{0, 3, 3, 3}), biosimage.New([]byte{0, 0, 0, 3}), nil)
		require.NoError(t, err)
		require.Equal(t, pkgbytes.Ranges{pkgbytes.Range{
			Offset: 2,
			Length: 1,
		}}, report)
	})

	t.Run("begin", func(t *testing.T) {
		report, err := Diff(pkgbytes.Ranges{
			pkgbytes.Range{
				Offset: 0,
				Length: 1,
			},
			pkgbytes.Range{
				Offset: 1,
				Length: 1,
			},
			pkgbytes.Range{
				Offset: 2,
				Length: 1,
			},
		}, noMapper{}, biosimage.New([]byte{0, 1, 2}), biosimage.New([]byte{2, 2, 2}), nil)
		require.NoError(t, err)
		require.Equal(t, pkgbytes.Ranges{pkgbytes.Range{
			Offset: 0,
			Length: 2,
		}}, report)
	})

	t.Run("end", func(t *testing.T) {
		report, err := Diff(pkgbytes.Ranges{
			pkgbytes.Range{
				Offset: 0,
				Length: 1,
			},
			pkgbytes.Range{
				Offset: 1,
				Length: 1,
			},
			pkgbytes.Range{
				Offset: 2,
				Length: 1,
			},
		}, noMapper{}, biosimage.New([]byte{0, 1, 2}), biosimage.New([]byte{0, 0, 0}), nil)
		require.NoError(t, err)
		require.Equal(t, pkgbytes.Ranges{pkgbytes.Range{
			Offset: 1,
			Length: 2,
		}}, report)
	})
}
