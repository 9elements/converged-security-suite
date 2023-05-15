package main

import (
	"fmt"
	"io/ioutil"

	"github.com/linuxboot/fiano/pkg/amd/manifest"
)

func parseAMDFirmwareFile(
	filePath string,
) (*manifest.AMDFirmware, error) {
	b, err := ioutil.ReadFile(filePath)
	if err != nil {
		return nil, fmt.Errorf("unable to read file '%s': %w", filePath, err)
	}

	return manifest.NewAMDFirmware(manifest.FirmwareImage(b))
}
