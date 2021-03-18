// +build integration

package uefi

import (
	"io"
	"os"
	"testing"

	fianoGUID "github.com/linuxboot/fiano/pkg/guid"
	"github.com/stretchr/testify/require"
	"github.com/ulikunitz/xz"
)

const testImagePath = `../../testdata/firmware/GALAGOPRO3.fd.xz`

func getTestImage(t *testing.T) *UEFI {
	xzFile, err := os.Open(testImagePath)
	require.NoError(t, err)

	r, err := xz.NewReader(xzFile)
	require.NoError(t, err)

	buf := make([]byte, 1<<23)
	n, err := r.Read(buf)
	if err != io.EOF {
		require.NoError(t, err)
	}

	firmware, err := ParseUEFIFirmwareBytes(buf[:n])
	require.NoError(t, err)

	return firmware
}

func TestFFSModuleName(t *testing.T) {
	uefi := getTestImage(t)

	check := func(guidString, expectedModuleName string) {
		nodes, err := uefi.GetByGUID(*fianoGUID.MustParse(guidString))
		require.NoError(t, err)
		require.Len(t, nodes, 1)
		node := nodes[0]

		moduleName := node.ModuleName()
		require.NotNil(t, moduleName)
		require.Equal(t, expectedModuleName, *moduleName)
	}

	// Just taking the last file of GALAGOPRO3. As we know it is named "SecCore".
	//
	// See also: pcr0tool printnodes ../testdata/firmware/GALAGOPRO3.fd
	check("1BA0062E-C779-4582-8566-336AE8F78F09", "SecCore")

	// And one module before it:
	check("C83BCE0E-6F16-4D3C-8D9F-4D6F5A032929", "BiosInfo")
}
