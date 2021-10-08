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
	FwPath   string `arg required name:"fwpath" help:"Path to UEFI firmware image." type:"path"`
	PSPLevel uint   `arg required name:"psp-level" help:"PSP Directory Level to use"`
}

type validatePSPEntriesCmd struct {
	FwPath     string   `arg required name:"fwpath" help:"Path to UEFI firmware image." type:"path"`
	PSPLevel   uint     `arg required name:"psp-level" help:"PSP Directory Level to use"`
	PSPEntries []string `arg required name:"validate-psp-entries" help:"Validates the signature of PSP entries given as argument." type:"list"`
}

type validateRTMCmd struct {
	FwPath    string `arg required name:"fwpath" help:"Path to UEFI firmware image." type:"path"`
	BIOSLevel uint   `arg required name:"bios-level" help:"BIOS Directory Level to use"`
}

type dumpPSPEntryCmd struct {
	FwPath    string `arg required name:"fwpath" help:"Path to UEFI firmware image." type:"path"`
	PSPEntry  string `arg required name:"dump_psp-entry" help:"dump PSP entry to system file." type:"string"`
	PSPLevel  uint   `arg required name:"psp-level" help:"PSP Directory Level to use"`
	EntryFile string `arg required name:"entry_path" help:"Path to entry file." type:"path"`
}

type patchPSPEntryCmd struct {
	FwPath               string `arg required name:"fwpath" help:"Path to UEFI firmware image." type:"path"`
	PSPEntry             string `arg required name:"patch-psp-entry" help:"dump PSP entry to system file." type:"string"`
	PSPLevel             uint   `arg required name:"psp-level" help:"PSP Directory Level to use"`
	EntryFile            string `arg required name:"modified_entry_path" help:"Path to modified entry file." type:"path"`
	ModifiedFirmwareFile string `arg required name:"modified_fwpath" help:"Path to UEFI firmware modified image." type:"path"`
}

var cli struct {
	Debug              bool                  `help:"Enable debug mode"`
	ShowKeys           showKeysCmd           `cmd help:"Shows all key known to the system, together with their origin"`
	ValidatePSPEntries validatePSPEntriesCmd `cmd help:"Validates signatures of PSP entries"`
	ValidateRTM        validateRTMCmd        `cmd help: Validated the signature of the extended RTM volume, which includes RTM and BIOS Directory Table`
	DumpPSPEntry       dumpPSPEntryCmd       `cmd help:"Dump an entry to a file on the filesystem"`
	PatchPSPEntry      patchPSPEntryCmd      `cmd help:"take a path on the filesystem pointing to a dump of a PSP entry and re-apply it to the firmware"`
}

func (s *showKeysCmd) Run(ctx *context) error {
	firmware, err := uefi.ParseUEFIFirmwareFile(s.FwPath)
	if err != nil {
		return fmt.Errorf("could not parse firmware image: %w", err)
	}

	keySet, err := psb.GetKeys(firmware, s.PSPLevel)
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

	signatureValidations, err := psb.ValidatePSPEntries(firmware, v.PSPLevel, v.PSPEntries)
	if err != nil {
		return err
	}

	for _, validation := range signatureValidations {
		fmt.Println(validation.String())
	}
	return nil

}

func (v *validateRTMCmd) Run(ctx *context) error {

	firmware, err := uefi.ParseUEFIFirmwareFile(v.FwPath)
	if err != nil {
		return fmt.Errorf("could not parse firmware image: %w", err)
	}

	signatureValidation, err := psb.ValidateRTM(firmware, v.BIOSLevel)
	if err != nil {
		return err
	}
	fmt.Println(signatureValidation.String())
	return nil
}

func (v *dumpPSPEntryCmd) Run(ctx *context) error {
	firmware, err := uefi.ParseUEFIFirmwareFile(v.FwPath)
	if err != nil {
		return fmt.Errorf("could not parse firmware image: %w", err)
	}

	n, err := psb.DumpPSPEntry(firmware, v.PSPLevel, v.PSPEntry, v.EntryFile)
	if err != nil {
		return err
	}
	fmt.Println("Entry size / Number of written bytes ", n)
	return nil
}

func (v *patchPSPEntryCmd) Run(ctx *context) error {
	firmware, err := uefi.ParseUEFIFirmwareFile(v.FwPath)
	if err != nil {
		return fmt.Errorf("could not parse firmware image: %w", err)
	}

	n, err := psb.PatchPSPEntry(firmware, v.PSPLevel, v.PSPEntry, v.EntryFile, v.ModifiedFirmwareFile)
	if err != nil {
		return err
	}
	fmt.Println("Firmware size / Number of written bytes ", n)
	return nil
}
