package tpmdetection

import (
	"bytes"
	"fmt"
	"io/ioutil"
	"os"
	"runtime"
	"strings"
)

type Type uint8

const (
	TypeNoTPM Type = iota
	TypeTPM12
	TypeTPM20
)

func (t Type) String() string {
	switch t {
	case TypeNoTPM:
		return "NoTPM"
	case TypeTPM12:
		return "TPM12"
	case TypeTPM20:
		return "TPM20"
	}
	panic(fmt.Sprintf("unknown TPM type: %d", t))
}

// AllTypes returns all values of Type enumeration
func AllTypes() []Type {
	return []Type{
		TypeNoTPM,
		TypeTPM12,
		TypeTPM20,
	}
}

// ActiveTypes returns all values that correspond to a possible TPM device of Type enumeration
func ActiveTypes() []Type {
	return []Type{
		TypeTPM12,
		TypeTPM20,
	}
}

// FromString converts tpm Type from a string
func FromString(s string) (Type, error) {
	switch strings.ToLower(s) {
	case "notpm":
		return TypeNoTPM, nil
	case "tpm12":
		return TypeTPM12, nil
	case "tpm20":
		return TypeTPM20, nil
	}
	return TypeNoTPM, fmt.Errorf("unsupported %s as tpm type", s)
}

// Local provides an easy way of TPM detection based on files heuristics
func Local() (Type, error) {
	if runtime.GOOS != "linux" {
		return 0, fmt.Errorf("tpm.DetectLocal is supported for Linux only")
	}
	return local("/dev/tpm0", "/sys/class/tpm/tpm0/device/caps")
}

func local(devicePath, capabilities string) (Type, error) {
	_, err := os.Stat(devicePath)
	if err != nil {
		if os.IsNotExist(err) {
			return TypeNoTPM, nil
		}
		return 0, fmt.Errorf("failed to check existance of %s, err: %w", devicePath, err)
	}

	caps, err := ioutil.ReadFile(capabilities)
	if err != nil {
		// This file may not exist for TPM2.0
		if os.IsNotExist(err) {
			return TypeTPM20, nil
		}
		return 0, fmt.Errorf("failed to check existance of %s, err: %w", capabilities, err)
	}

	specPrefix := "TCG version"
	var tpmVersion string
	for _, lineBytes := range bytes.Split(caps, []byte{'\n'}) {
		line := string(lineBytes)
		parts := strings.SplitN(line, ":", 2)
		key := strings.TrimSpace(parts[0])
		val := strings.TrimSpace(parts[1])
		if key == specPrefix {
			tpmVersion = val
			break
		}
	}
	if tpmVersion == "2.0" {
		return TypeTPM20, nil
	}
	// should be 1.2, because the capabilities file should not even exist for TPM2.0
	return TypeTPM12, nil
}
