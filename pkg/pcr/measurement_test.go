package pcr

import (
	"testing"

	"github.com/stretchr/testify/require"

	pkgbytes "github.com/9elements/converged-security-suite/v2/pkg/bytes"
)

func TestMeasurements_FindOverlapping(t *testing.T) {
	t.Run("simple_case", func(t *testing.T) {
		measurements := Measurements{
			{
				ID: MeasurementIDACMDate,
				Data: DataChunks{
					{
						Range: pkgbytes.Range{
							Offset: 0x00,
							Length: 0x10,
						},
					},
					{
						Range: pkgbytes.Range{
							Offset: 0x60,
							Length: 0x10,
						},
					},
					{
						Range: pkgbytes.Range{
							Offset: 0xa0,
							Length: 0x10,
						},
					},
				},
			},
			{
				ID: MeasurementIDFITPointer,
				Data: DataChunks{
					{
						Range: pkgbytes.Range{
							Offset: 0x41,
							Length: 0x10,
						},
					},
				},
			},
			{
				ID: MeasurementIDFITHeaders,
				Data: DataChunks{
					{
						Range: pkgbytes.Range{
							Offset: 0x5e,
							Length: 0x10,
						},
					},
				},
			},
			{
				ID: MeasurementIDDXE,
				Data: DataChunks{
					{
						Range: pkgbytes.Range{
							Offset: 0x65,
							Length: 0x10,
						},
					},
				},
			},
		}

		require.Equal(t, Measurements{
			measurements[1],
			measurements[2],
		}, measurements.FindOverlapping(pkgbytes.Range{
			Offset: 0x50,
			Length: 0x0f,
		}))
	})
}
