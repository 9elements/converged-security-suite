package diff

import (
	"testing"

	pkgbytes "github.com/9elements/converged-security-suite/v2/pkg/bytes"
	"github.com/stretchr/testify/require"
)

func TestDiff(t *testing.T) {
	t.Run("arbitraryOrder", func(t *testing.T) {
		require.Equal(t, pkgbytes.Ranges{pkgbytes.Range{
			Offset: 2,
			Length: 1,
		}}, Diff(pkgbytes.Ranges{
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
		}, []byte{0, 3, 3, 3}, []byte{0, 0, 0, 3}, nil))
	})

	t.Run("begin", func(t *testing.T) {
		require.Equal(t, pkgbytes.Ranges{pkgbytes.Range{
			Offset: 0,
			Length: 2,
		}}, Diff(pkgbytes.Ranges{
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
		}, []byte{0, 1, 2}, []byte{2, 2, 2}, nil))
	})

	t.Run("end", func(t *testing.T) {
		require.Equal(t, pkgbytes.Ranges{pkgbytes.Range{
			Offset: 1,
			Length: 2,
		}}, Diff(pkgbytes.Ranges{
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
		}, []byte{0, 1, 2}, []byte{0, 0, 0}, nil))
	})
}
