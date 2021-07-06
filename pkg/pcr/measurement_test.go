package pcr

import (
	"crypto/sha1"
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

func TestMeasurements_Calculate(t *testing.T) {
	var measurements Measurements = []*Measurement{
		{
			ID: MeasurementIDInit,
		},
		{
			ID:   MeasurementIDPCR0DATA,
			Data: DataChunks{*NewStaticDataChunk(0, []byte{0})},
		},
	}

	require.Equal(t,
		measurements.Calculate(nil, 0, sha1.New(), nil),
		[]byte{
			0xa8, 0x9f, 0xb8, 0xf8, 0x8c, 0xaa, 0x95, 0x90, 0xe6, 0x12,
			0x9b, 0x63, 0x3b, 0x14, 0x4a, 0x68, 0x51, 0x44, 0x90, 0xd5,
		},
	)
}

func TestCalculatePCR(t *testing.T) {
	ms := []MeasureEvent{
		&Measurement{
			ID: MeasurementIDInit,
		},
		&Measurement{
			ID:   MeasurementIDPCR0DATA,
			Data: DataChunks{*NewStaticDataChunk(0, []byte{0})},
		},
	}

	hash, err := CalculatePCR(nil, 0, ms, sha1.New(), nil)
	require.NoError(t, err)
	require.Equal(t,
		hash,
		[]byte{
			0xa8, 0x9f, 0xb8, 0xf8, 0x8c, 0xaa, 0x95, 0x90, 0xe6, 0x12,
			0x9b, 0x63, 0x3b, 0x14, 0x4a, 0x68, 0x51, 0x44, 0x90, 0xd5,
		},
	)
}

func TestCalculatePCRWithCachedMeasurement(t *testing.T) {
	image := []byte{}
	hasher := sha1.New()

	pcr0data, err := (&Measurement{
		ID:   MeasurementIDPCR0DATA,
		Data: DataChunks{*NewStaticDataChunk(0, []byte{0})},
	}).Cache(image, hasher)
	require.NoError(t, err)

	ms := []MeasureEvent{
		&Measurement{
			ID: MeasurementIDInit,
		},
		pcr0data,
	}

	hash, err := CalculatePCR(image, 0, ms, hasher, nil)
	require.NoError(t, err)
	require.Equal(t,
		hash,
		[]byte{
			0xa8, 0x9f, 0xb8, 0xf8, 0x8c, 0xaa, 0x95, 0x90, 0xe6, 0x12,
			0x9b, 0x63, 0x3b, 0x14, 0x4a, 0x68, 0x51, 0x44, 0x90, 0xd5,
		},
	)
}
