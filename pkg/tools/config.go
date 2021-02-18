package tools

import (
	"encoding/json"
	"fmt"
	"io/ioutil"

	"github.com/9elements/converged-security-suite/v2/pkg/hwapi"
	"github.com/google/go-tpm/tpm2"
)

// Configuration input
type Configuration struct {
	TPM     hwapi.TPMVersion
	TXTMode TXTMode
	LCPHash tpm2.Algorithm
}

// Configuration input
type jsonConfig struct {
	TPM      string
	TXTMode  string
	LCP2Hash string
}

// ParseConfig parses txt-suite configuration file
func ParseConfig(filepath string) (*Configuration, error) {
	var jConfig jsonConfig
	var config Configuration
	data, err := ioutil.ReadFile(filepath)
	if err != nil {
		return nil, err
	}
	err = json.Unmarshal(data, &jConfig)
	if err != nil {
		return nil, err
	}
	if jConfig.TPM == "1.2" {
		config.TPM = hwapi.TPMVersion12
	} else if jConfig.TPM == "2.0" {
		config.TPM = hwapi.TPMVersion20
	} else {
		return nil, fmt.Errorf("Couldn't parse TPM option: %s", jConfig.TPM)
	}
	if jConfig.TXTMode == "auto" {
		config.TXTMode = AutoPromotion
	} else if jConfig.TXTMode == "signed" {
		config.TXTMode = SignedPolicy
	} else {
		return nil, fmt.Errorf("Couldn't parse TXT mode option: %s", jConfig.TXTMode)
	}
	if jConfig.LCP2Hash == "SHA1" {
		config.LCPHash = tpm2.AlgSHA1
	} else if jConfig.LCP2Hash == "SHA256" {
		config.LCPHash = tpm2.AlgSHA256
	} else if jConfig.LCP2Hash == "SHA384" {
		config.LCPHash = tpm2.AlgSHA384
	} else if jConfig.LCP2Hash == "SM3" {
		// SM3 is not implemented
		//config.LCPHash = tpm2.AlgSM3
	} else if jConfig.LCP2Hash == "NULL" {
		config.LCPHash = tpm2.AlgNull
	} else {
		return nil, fmt.Errorf("Couldn't parse LCP hash option: %s", jConfig.LCP2Hash)
	}
	return &config, nil
}
