package tpm

import (
	"bytes"
	"fmt"
	"io/ioutil"
	"os"
	"runtime"
	"strings"
)

type DetectedTPM uint8

const (
	DetectedNoTPM DetectedTPM = iota
	DetectedTPM12
	DetectedTPM20
)

// DetectLocal provides an easy way of TPM detection based on files heuristics
func DetectLocal() (DetectedTPM, error) {
	if runtime.GOOS != "linux" {
		return 0, fmt.Errorf("tpm.DetectLocal is supported for Linux only")
	}

	_, err := os.Stat("/dev/tpm0")
	if err != nil {
		if os.IsNotExist(err) {
			return DetectedNoTPM, nil
		}
		return 0, fmt.Errorf("failed to check existance of /dev/tpm0, err: %v", err)
	}

	caps, err := ioutil.ReadFile("/sys/class/tpm/tpm0/device/caps")
	if err != nil {
		// This file may not exist for TPM2.0
		if os.IsNotExist(err) {
			return DetectedTPM20, nil
		}
		return 0, fmt.Errorf("failed to check existance of /sys/class/tpm/tpm0/device/caps, err: %v", err)
	}

	specPrefix := "TCG version: "
	var tpmVersion string
	for _, lineBytes := range bytes.Split(caps, []byte{'\n'}) {
		line := string(lineBytes)
		if strings.HasPrefix(line, specPrefix) {
			tpmVersion = line[len(specPrefix):]
		}
	}
	if tpmVersion == "2.0" {
		return DetectedTPM20, nil
	}
	return DetectedTPM12, nil
}
