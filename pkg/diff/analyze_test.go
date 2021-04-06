package diff

import (
	"testing"

	pkgbytes "github.com/9elements/converged-security-suite/v2/pkg/bytes"
	"github.com/9elements/converged-security-suite/v2/pkg/pcr"
	"github.com/9elements/converged-security-suite/v2/pkg/uefi/ffs"
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

type dummyFirmware []byte

func (f dummyFirmware) Buf() []byte {
	return f
}

func (f dummyFirmware) GetByRange(byteRange pkgbytes.Range) (nodes []*ffs.Node, err error) {
	for i := uint64(0); i < byteRange.Length; i++ {
		nodes = append(nodes, &ffs.Node{
			Range: pkgbytes.Range{
				Offset: i,
				Length: 1,
			},
		})
	}
	return
}
func (f dummyFirmware) NameToRangesMap() map[string]pkgbytes.Ranges {
	return map[string]pkgbytes.Ranges{}
}

func TestAnalysisReportAddOffset(t *testing.T) {
	report0 := Analyze(
		pkgbytes.Ranges{{
			Offset: 4,
			Length: 1,
		}},
		pcr.Measurements{{
			Data: pcr.DataChunks{{
				Range: pkgbytes.Range{
					Offset: 1,
					Length: 8,
				},
			}},
		}},
		dummyFirmware([]byte{0, 0, 0, 0, 1, 0, 0, 0, 0, 0}),
		make([]byte, 10),
	)

	report1 := Analyze(
		pkgbytes.Ranges{{
			Offset: 5,
			Length: 1,
		}},
		pcr.Measurements{{
			Data: pcr.DataChunks{{
				Range: pkgbytes.Range{
					Offset: 2,
					Length: 8,
				},
			}},
		}},
		dummyFirmware([]byte{0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0}),
		make([]byte, 11),
	)
	report1.AddOffset(-1)

	require.Equal(t,
		report0,
		report1,
	)
}
