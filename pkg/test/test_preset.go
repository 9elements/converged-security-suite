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
	if config.TPM == "1.2" {
		preset.TPM = hwapi.TPMVersion12
	} else if config.TPM == "2.0" {
		preset.TPM = hwapi.TPMVersion20
	} else {
		return nil, fmt.Errorf("couldn't parse TPM option: %s", config.TPM)
	}
	if config.TXTMode == "auto" {
		preset.TXTMode = tools.AutoPromotion
	} else if config.TXTMode == "signed" {
		preset.TXTMode = tools.SignedPolicy
	} else {
		return nil, fmt.Errorf("couldn't parse TXT mode option: %s", config.TXTMode)
	}
	if config.LCP2Hash == "SHA1" {
		preset.LCPHash = tpm2.AlgSHA1
	} else if config.LCP2Hash == "SHA256" {
		preset.LCPHash = tpm2.AlgSHA256
	} else if config.LCP2Hash == "SHA384" {
		preset.LCPHash = tpm2.AlgSHA384
	} else if config.LCP2Hash == "SM3" {
		// SM3 is not implemented
		// config.LCPHash = tpm2.AlgSM3
	} else if config.LCP2Hash == "NULL" {
		preset.LCPHash = tpm2.AlgNull
	} else {
		return nil, fmt.Errorf("couldn't parse LCP hash option: %s", config.LCP2Hash)
	}
	return &preset, nil
}
