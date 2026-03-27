package test

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/9elements/converged-security-suite/v2/pkg/tools"
	"github.com/9elements/go-linux-lowlevel-hw/pkg/hwapi"
	"github.com/google/go-tpm/legacy/tpm2"
)

// PreSet set of pre-defined assumptions
type PreSet struct {
	TPM                hwapi.TPMVersion
	TXTMode            tools.TXTMode
	LCPHash            tpm2.Algorithm
	Firmware           []byte
	HostBridgeDeviceID uint16
	Strict             bool
}

// PreSetJSON configuration input
type PreSetJSON struct {
	TPM      string `json:",omitempty"`
	TXTMode  string `json:",omitempty"`
	LCP2Hash string `json:",omitempty"`
}

// ParsePreSet parses txt-suite configuration file
func ParsePreSet(filepath string) (*PreSet, error) {
	var preset PreSet
	var config PreSetJSON
	data, err := os.ReadFile(filepath)
	if err != nil {
		return nil, err
	}
	err = json.Unmarshal(data, &config)
	if err != nil {
		return nil, err
	}
	switch config.TPM {
	case "1.2":
		preset.TPM = hwapi.TPMVersion12
	case "2.0":
		preset.TPM = hwapi.TPMVersion20
	}
	switch config.TXTMode {
	case "auto":
		preset.TXTMode = tools.AutoPromotion
	case "signed":
		preset.TXTMode = tools.SignedPolicy
	default:
		return nil, fmt.Errorf("couldn't parse TXT mode option: %s", config.TXTMode)
	}
	switch config.LCP2Hash {
	case "SHA1":
		preset.LCPHash = tpm2.AlgSHA1
	case "SHA256":
		preset.LCPHash = tpm2.AlgSHA256
	case "SHA384":
		preset.LCPHash = tpm2.AlgSHA384
	case "SM3":
		// SM3 is not implemented
	case "NULL":
		preset.LCPHash = tpm2.AlgNull
	default:
		return nil, fmt.Errorf("couldn't parse LCP hash option: %s", config.LCP2Hash)
	}
	return &preset, nil
}
