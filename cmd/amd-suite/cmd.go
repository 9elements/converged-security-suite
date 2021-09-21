package main

import (
	"fmt"

	"github.com/9elements/converged-security-suite/v2/pkg/amd/psb"

	"github.com/9elements/converged-security-suite/pkg/uefi"
)

// Context for kong command line parser
type context struct {
	debug bool
}

type showKeysCmd struct {
	FwPath string `arg required name:"fwpath" help:"Path to UEFI firmware image." type:"path"`
}

type validatePSPEntriesCmd struct {
	FwPath     string   `arg required name:"fwpath" help:"Path to UEFI firmware image." type:"path"`
	PSPEntries []string `arg required name:"validate-psp-entries" help:"Validates the signature of PSP entries given as argument." type:"list"`
}

var cli struct {
	Debug              bool                  `help:"Enable debug mode"`
	ShowKeys           showKeysCmd           `cmd help:"Shows all key known to the system, together with their origin"`
	ValidatePSPEntries validatePSPEntriesCmd `cmd help:"Validates signatures of PSP entries"`
}

func (s *showKeysCmd) Run(ctx *context) error {
	firmware, err := uefi.ParseUEFIFirmwareFile(s.FwPath)
	if err != nil {
		return fmt.Errorf("could not parse firmware image: %w", err)
	}

	keySet, err := psb.GetKeys(firmware)
	if err != nil {
		return fmt.Errorf("could not extract keys from the firmware image: %w", err)
	}

	fmt.Println(keySet.String())
	return nil
}

func (v *validatePSPEntriesCmd) Run(ctx *context) error {
	firmware, err := uefi.ParseUEFIFirmwareFile(v.FwPath)
	if err != nil {
		return fmt.Errorf("could not parse firmware image: %w", err)
	}

	signatureValidations, err := psb.ValidatePSPEntries(firmware, v.PSPEntries)
	if err != nil {
		return err
	}

	for _, validation := range signatureValidations {
		fmt.Println(validation.String())
	}
	return nil

}
