package tools

import (
	"encoding/json"
	"fmt"
	"github.com/9elements/converged-security-suite/v2/pkg/hwapi"
	"io/ioutil"
)

// Configuration input
type Configuration struct {
	TPM     hwapi.TPMVersion
	TXTMode TXTMode
	LCPHash LCPPol2Hash
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
		config.LCPHash = LCPPol2HAlgSHA1
	} else if jConfig.LCP2Hash == "SHA256" {
		config.LCPHash = LCPPol2HAlgSHA256
	} else if jConfig.LCP2Hash == "SHA384" {
		config.LCPHash = LCPPol2HAlgSHA384
	} else if jConfig.LCP2Hash == "SM3" {
		config.LCPHash = LCPPol2HAlgSM3
	} else if jConfig.LCP2Hash == "NULL" {
		config.LCPHash = LCPPol2HAlgNULL
	} else {
		return nil, fmt.Errorf("Couldn't parse LCP hash option: %s", jConfig.LCP2Hash)
	}
	return &config, nil
}
