package main

import (
	"fmt"
	"os"
	"strconv"

	"github.com/9elements/converged-security-suite/v2/pkg/amd/psb"

	"github.com/9elements/converged-security-suite/v2/pkg/uefi"

	amd_manifest "github.com/linuxboot/fiano/pkg/amd/manifest"
)

// Context for kong command line parser
type context struct {
	debug bool
}

type outputFirmwareCmd struct {
	FwPath string `required name:"fwpath" help:"Path to UEFI firmware image." type:"path"`
}

type showKeysCmd struct {
	FwPath   string `required name:"fwpath" help:"Path to UEFI firmware image." type:"path"`
	PSPLevel uint   `required name:"psp-level" help:"PSP Directory Level to use"`
}

type validatePSPEntriesCmd struct {
	FwPath     string   `required name:"fwpath" help:"Path to UEFI firmware image." type:"path"`
	PSPLevel   uint     `required name:"psp-level" help:"PSP Directory Level to use"`
	PSPEntries []string `arg required name:"psp-entries-hex-codes" help:"Hex codes of PSP entries to validate" type:"list"`
}

type validateRTMCmd struct {
	FwPath    string `required name:"fwpath" help:"Path to UEFI firmware image." type:"path"`
	BIOSLevel uint   `required name:"bios-level" help:"BIOS Directory Level to use"`
}

type dumpEntryCmd struct {
	FwPath    string `required name:"fwpath" help:"Path to UEFI firmware image." type:"path"`
	Level     uint   `required name:"level" help:"Directory Level to use"`
	EntryFile string `required name:"entry-path" help:"Path to entry file." type:"path"`
	Type      string `required name:"type" help:"Type of entry to be dumped, either from PSP or BIOS directory (psp|bios)" type:"string"`
	Entry     string `arg name:"entry-hex-code" help:"Hex code of the entry to dump" type:"string"`
}

type patchEntryCmd struct {
	FwPath               string `required name:"fwpath" help:"Path to UEFI firmware image." type:"path"`
	Level                uint   `required name:"level" help:"Directory Level to use"`
	EntryFile            string `required name:"modified-entry-path" help:"Path to modified entry file." type:"path"`
	ModifiedFirmwareFile string `required name:"modified-fwpath" help:"Path to UEFI firmware modified image." type:"path"`
	Type                 string `required name:"type" help:"Type of entry to be dumped, either from PSP or BIOS directory (psp|bios)" type:"string"`
	Entry                string `arg required name:"entry-hex-code" help:"Hex code of entry to patch" type:"string"`
}

var cli struct {
	Debug              bool                  `help:"Enable debug mode"`
	ShowKeys           showKeysCmd           `cmd help:"Shows all key known to the system, together with their origin"`
	ValidatePSPEntries validatePSPEntriesCmd `cmd help:"Validates signatures of PSP entries"`
	ValidateRTM        validateRTMCmd        `cmd help: Validated the signature of the extended RTM volume, which includes RTM and BIOS Directory Table`
	OutputFirmware     outputFirmwareCmd     `cmd help:"Outputs information about the firmware and PSP/BIOS structure"`
	DumpEntry          dumpEntryCmd          `cmd help:"Dump an entry, either BIOS or PSP, to a file on the filesystem"`
	PatchEntry         patchEntryCmd         `cmd help:"take a path on the filesystem pointing to a dump of a BIOS or PSP entry and re-apply it to the firmware"`
}

func parseAmdFw(path string) (*amd_manifest.AMDFirmware, error) {
	firmware, err := uefi.ParseUEFIFirmwareFile(path)
	if err != nil {
		return nil, fmt.Errorf("could not parse firmware image: %w", err)
	}
	amdFw, err := amd_manifest.NewAMDFirmware(firmware)
	if err != nil {
		return nil, fmt.Errorf("could not parse AMD Firmware: %w", err)
	}

	return amdFw, nil
}

func (s *outputFirmwareCmd) Run(ctx *context) error {
	amdFw, err := parseAmdFw(s.FwPath)
	if err != nil {
		return fmt.Errorf("could not parse firmware image: %w", err)
	}

	err = psb.OutputPSPEntries(amdFw)
	if err != nil {
		return fmt.Errorf("could not output PSP firmware info: %w", err)
	}

	err = psb.OutputBIOSEntries(amdFw)
	if err != nil {
		return fmt.Errorf("could not output BIOS firmware info: %w", err)
	}

	return nil
}

func (s *showKeysCmd) Run(ctx *context) error {
	amdFw, err := parseAmdFw(s.FwPath)
	if err != nil {
		return fmt.Errorf("could not parse firmware image: %w", err)
	}

	keySet, err := psb.GetKeys(amdFw, s.PSPLevel)
	if err != nil {
		return fmt.Errorf("could not extract keys from the firmware image: %w", err)
	}

	fmt.Println(keySet.String())
	return nil
}

func (v *validatePSPEntriesCmd) Run(ctx *context) error {

	amdFw, err := parseAmdFw(v.FwPath)
	if err != nil {
		return fmt.Errorf("could not parse firmware image: %w", err)
	}

	signatureValidations, err := psb.ValidatePSPEntries(amdFw, v.PSPLevel, v.PSPEntries)
	if err != nil {
		return err
	}

	for _, validation := range signatureValidations {
		fmt.Println(validation.String())
	}
	return nil

}

func (v *validateRTMCmd) Run(ctx *context) error {

	amdFw, err := parseAmdFw(v.FwPath)
	if err != nil {
		return fmt.Errorf("could not parse firmware image: %w", err)
	}

	signatureValidation, err := psb.ValidateRTM(amdFw, v.BIOSLevel)
	if err != nil {
		return err
	}
	fmt.Println(signatureValidation.String())
	return nil
}

func (v *dumpEntryCmd) Run(ctx *context) error {

	amdFw, err := parseAmdFw(v.FwPath)
	if err != nil {
		return fmt.Errorf("could not parse firmware image: %w", err)
	}

	id, err := strconv.ParseInt(v.Entry, 16, 64)
	if err != nil {
		return fmt.Errorf("could not parse hexadecimal entry (%s) : %w", v.Entry, err)
	}

	f, err := os.Create(v.EntryFile)
	if err != nil {
		return fmt.Errorf("could not create file `%s` for dumping entry %x: %w", v.EntryFile, id, err)
	}
	defer func() {
		err := f.Close()
		if err != nil {
			fmt.Printf("could not close file %s after dumping entry %x", v.EntryFile, id)
		}
	}()

	n, err := psb.DumpEntry(amdFw, v.Level, v.Type, uint64(id), f)
	if err != nil {
		return err
	}
	fmt.Println("Entry size / Number of written bytes ", n)
	return nil
}

func (v *patchEntryCmd) Run(ctx *context) error {
	amdFw, err := parseAmdFw(v.FwPath)
	if err != nil {
		return fmt.Errorf("could not parse firmware image: %w", err)
	}

	id, err := strconv.ParseInt(v.Entry, 16, 64)
	if err != nil {
		return fmt.Errorf("could not parse hexadecimal entry (%s) : %w", v.Entry, err)
	}

	inFile, err := os.Open(v.EntryFile)
	if err != nil {
		return fmt.Errorf("could not read modified entry file: %w", err)
	}

	outFile, err := os.Create(v.ModifiedFirmwareFile)
	if err != nil {
		return fmt.Errorf("could not create file `%s` for patched firmware: %w", v.ModifiedFirmwareFile, err)
	}
	defer func() {
		err := outFile.Close()
		if err != nil {
			fmt.Printf("could not close file %s after dumping entry %x", v.EntryFile, id)
		}
	}()

	n, err := psb.PatchEntry(amdFw, v.Level, v.Type, uint64(id), inFile, outFile)
	if err != nil {
		return err
	}
	fmt.Println("Firmware size / Number of written bytes ", n)
	return nil
}
