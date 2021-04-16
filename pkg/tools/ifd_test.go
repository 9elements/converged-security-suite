// +build go1.16

package tools

import (
	"log"
	"testing"

	"github.com/9elements/converged-security-suite/v2/testdata/firmware"
	"github.com/stretchr/testify/require"
)

type panicWriter struct{}

func (panicWriter) Write(b []byte) (int, error) {
	panic("PANIC")
}

// TestCalcImageOffsetNoLogGarbage checks if fiano sends any garbage into `log`.
// See: https://github.com/linuxboot/fiano/issues/330
func TestCalcImageOffsetNoLogGarbage(t *testing.T) {
	log.SetOutput(panicWriter{})

	img, err := firmware.GetTestImage("../../testdata/firmware/coreboot.fd.xz")
	require.NoError(t, err)

	_, err = CalcImageOffset(img, 1)
	require.NoError(t, err)
}
