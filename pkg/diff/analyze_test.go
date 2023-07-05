package diff

import (
	"testing"

	"github.com/9elements/converged-security-suite/v2/pkg/bootflow/systemartifacts/biosimage"
	pkgbytes "github.com/linuxboot/fiano/pkg/bytes"
	"github.com/stretchr/testify/require"
)

func TestHammingDistance(t *testing.T) {
	t.Run("simple_case", func(t *testing.T) {
		require.Equal(t, uint64(8), hammingDistance([]byte{1, 2, 4, 8}, []byte{3, 3, 3, 3}, nil, nil))
	})
	t.Run("different_length", func(t *testing.T) {
		require.Equal(t, uint64(8), hammingDistance([]byte{1, 2, 4, 8, 8}, []byte{3, 3, 3, 3}, nil, nil))
		require.Equal(t, uint64(8), hammingDistance([]byte{1, 2, 4, 8}, []byte{3, 3, 3, 3, 3}, nil, nil))
	})
	t.Run("exclude_a", func(t *testing.T) {
		require.Equal(t, uint64(6), hammingDistance([]byte{1, 2, 4, 8}, []byte{3, 3, 3, 3}, []byte{1, 2}, nil))
	})
	t.Run("exclude_b", func(t *testing.T) {
		require.Equal(t, uint64(2), hammingDistance([]byte{1, 2, 4, 8}, []byte{3, 3, 1, 2}, nil, []byte{1, 2}))
	})
}

//nolint:typecheck
func TestAnalysisReportAddOffset(t *testing.T) {
	report0, err := Analyze(
		pkgbytes.Ranges{{
			Offset: 4,
			Length: 1,
		}},
		noMapper{},
		Measurements{{
			Chunks: DataChunks{{
				Reference: pkgbytes.Range{
					Offset: 1,
					Length: 8,
				},
			}},
		}},
		biosimage.New([]byte{0, 0, 0, 0, 1, 0, 0, 0, 0, 0}),
		biosimage.New(make([]byte, 10)),
	)
	require.NoError(t, err)

	report1, err := Analyze(
		pkgbytes.Ranges{{
			Offset: 5,
			Length: 1,
		}},
		noMapper{},
		Measurements{{
			Chunks: DataChunks{{
				Reference: pkgbytes.Range{
					Offset: 2,
					Length: 8,
				},
			}},
		}},
		biosimage.New([]byte{0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0}),
		biosimage.New(make([]byte, 11)),
	)
	require.NoError(t, err)
	report1.AddOffset(-1)

	require.Equal(t,
		report0,
		report1,
	)
}
