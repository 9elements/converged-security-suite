// +build longtest

package pcr

import (
	"io"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/ulikunitz/xz"

	"github.com/9elements/converged-security-suite/v2/pkg/uefi"
)

const (
	imagePath = "../../../testdata/firmware/GALAGOPRO3.fd.xz"
)

func getTestImage(t *testing.T) Firmware {
	xzFile, err := os.Open(imagePath)
	require.NoError(t, err)

	r, err := xz.NewReader(xzFile)
	require.NoError(t, err)

	buf := make([]byte, 1<<23)
	n, err := r.Read(buf)
	if err != io.EOF {
		require.NoError(t, err)
	}

	firmware, err := uefi.ParseUEFIFirmwareBytes(buf[:n])
	require.NoError(t, err)

	return firmware
}

// TestUEFI_GetPCRMeasurements checks if a PCR value could be changed
// by changing a byte outside of byte ranges reported by GetPCRMeasurements.
//
// If it is possible, then it's an error in the code (which should be fixed).
func TestUEFI_GetPCRMeasurements(t *testing.T) {
	firmware := getTestImage(t)

	measurementOpts := []MeasureOption{SetFlow(FlowIntelLegacyTXTEnabled)}
	for pcrID := ID(0); pcrID < ^ID(0); pcrID++ {
		t.Run(pcrID.String(), func(t *testing.T) {
			measurements, _, _, _ := GetMeasurements(firmware, pcrID, measurementOpts...)
			if measurements == nil {
				return // this pcrID calculation is not implemented, yet
			}

			assert.Nil(t, findMissingFakeMeasurements(firmware, pcrID, measurements, measurementOpts...))
		})
	}
}

// TODO: add also a test based on real runs on QEMU
