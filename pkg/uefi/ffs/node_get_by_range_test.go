package ffs_test

import (
	"testing"

	"github.com/9elements/converged-security-suite/v2/pkg/uefi"
	"github.com/9elements/converged-security-suite/v2/testdata/firmware"
	pkgbytes "github.com/linuxboot/fiano/pkg/bytes"
	"github.com/stretchr/testify/assert"
)

func TestNodeGetNamesByRange(t *testing.T) {
	t.Run("simple", func(t *testing.T) {
		fw, err := uefi.ParseUEFIFirmwareBytes(firmware.FakeIntelFirmware)
		assert.NoError(t, err)

		nodes, err := fw.GetByRange(pkgbytes.Range{
			Offset: 0,
			Length: 1,
		})
		assert.NoError(t, err)
		assert.Len(t, nodes, 2)
	})

	t.Run("with_offset", func(t *testing.T) {
		fw, err := uefi.ParseUEFIFirmwareBytes(firmware.FakeIntelFirmware)
		assert.NoError(t, err)

		fw.AddOffset = 1 << 30
		nodes, err := fw.GetByRange(pkgbytes.Range{
			Offset: 1 << 30,
			Length: 1,
		})
		assert.NoError(t, err)
		assert.Len(t, nodes, 2)
	})
}
