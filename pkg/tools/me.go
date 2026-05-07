package tools

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/prometheus/procfs/sysfs"
)

type MEVersion uint8

const (
	Version16 MEVersion = 16
	Version18 MEVersion = 18
	Version21 MEVersion = 21
)

func GetMEVersion() (MEVersion, error) {
	fs, err := sysfs.NewFS("/sys")
	if err != nil {
		return 0, err
	}

	mei, err := fs.MEIClass()
	if err != nil {
		return 0, err
	}

	// There can be (theoretically) more than one MEI devices.
	// We onlly need the version of one of it.
	var fwVersion string
	for _, dev := range *mei {
		fwVersion = *dev.FWVersion
		break
	}

	// There are always 4 lines in fw_version (no clue why) exposed in sysfs.
	// So lets take the first line and then look for what is interesting for us,
	// i.e. 0:N where N is one of the defined MEVersion's
	fline := strings.Split(fwVersion, "\n")
	felem := strings.Split(fline[0], ".")
	pref := strings.Split(felem[0], ":")

	ver, err := strconv.Atoi(pref[1])
	if err != nil {
		return 0, err
	}

	switch ver {
	case 16:
		return Version16, nil
	case 18:
		return Version18, nil
	case 21:
		return Version21, nil
	}

	return 0, fmt.Errorf("unknown ME version")
}
