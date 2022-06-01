package main

import (
	"fmt"
	"io"
	"os"
	"strconv"

	"github.com/9elements/converged-security-suite/v2/pkg/amd/apcb"
	"github.com/9elements/converged-security-suite/v2/pkg/amd/psb"

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
	FwPath   string `required name:"fwpath"    help:"Path to UEFI firmware image." type:"path"`
	PSPLevel uint   `required name:"psp-level" help:"PSP Directory Level to use"`
}

type outputAPCBSecurityTokensCmd struct {
	FwPath    string `required name:"fwpath"     help:"Path to UEFI firmware image." type:"path"`
	BIOSLevel uint   `required name:"bios-level" help:"PSP Directory Level to use"`
}

type validatePSPEntriesCmd struct {
	FwPath        string   `required name:"fwpath"                    help:"Path to UEFI firmware image." type:"path"`
	KeyDBPSPLevel uint     `required name:"keydb-psp-level"           help:"PSP Directory Level to use for key database"`
	Directory     string   `required name:"directory"                 help:"Directory to check items in: PSPDirectoryLevel1|PSPDirectoryLevel2|BIOSDirectoryLevel1|BIOSDirectoryLevel2"`
	PSPEntries    []string `arg required name:"psp-entries-hex-codes" help:"Hex codes of PSP entries to validate" type:"list"`
}

type validateRTMCmd struct {
	FwPath    string `required name:"fwpath"     help:"Path to UEFI firmware image." type:"path"`
	BIOSLevel uint   `required name:"bios-level" help:"BIOS Directory Level to use"`
}

type dumpPSPEntryCmd struct {
	FwPath    string `required name:"fwpath"     help:"Path to UEFI firmware image." type:"path"`
	PSPLevel  uint   `required name:"psp-level"  help:"PSP Directory Level to use"`
	EntryFile string `required name:"entry-path" help:"Path to entry file." type:"path"`
	Entry     string `arg name:"entry-hex-code"  help:"Hex code of the entry to dump" type:"string"`
}

type dumpBIOSEntryCmd struct {
	FwPath    string `required name:"fwpath"     help:"Path to UEFI firmware image." type:"path"`
	BIOSLevel uint   `required name:"bios-level" help:"PSP Directory Level to use"`
	EntryFile string `required name:"entry-path" help:"Path to entry file." type:"path"`
	Instance  uint8  `optional name:"instance"   help:"Path to entry file."`
	Entry     string `arg name:"entry-hex-code"  help:"Hex code of the entry to dump" type:"string"`
}

type patchPSPEntryCmd struct {
	FwPath               string `required name:"fwpath"              help:"Path to UEFI firmware image." type:"path"`
	EntryFile            string `required name:"modified-entry-path" help:"Path to modified entry file." type:"path"`
	ModifiedFirmwareFile string `required name:"modified-fwpath"     help:"Path to UEFI firmware modified image." type:"path"`
	PSPLevel             uint   `required name:"psp-level"           help:"PSP Directory Level to use"`
	Entry                string `arg required name:"entry-hex-code"  help:"Hex code of entry to patch" type:"string"`
}

type patchBIOSEntryCmd struct {
	FwPath               string `required name:"fwpath"              help:"Path to UEFI firmware image." type:"path"`
	EntryFile            string `required name:"modified-entry-path" help:"Path to modified entry file." type:"path"`
	ModifiedFirmwareFile string `required name:"modified-fwpath"     help:"Path to UEFI firmware modified image." type:"path"`
	BIOSLevel            uint   `required name:"bios-level"          help:"BIOS Directory Level to use"`
	Instance             uint8  `optional name:"instance"            help:"Path to entry file."`
	Entry                string `arg required name:"entry-hex-code"  help:"Hex code of entry to patch" type:"string"`
}

var cli struct {
	Debug                     bool                        `help:"Enable debug mode"`
	ShowKeys                  showKeysCmd                 `cmd help:"Shows all key known to the system, together with their origin"`
	ValidatePSPEntries        validatePSPEntriesCmd       `cmd help:"Validates signatures of PSP entries"`
	ValidateRTM               validateRTMCmd              `cmd help: Validated the signature of the extended RTM volume, which includes RTM and BIOS Directory Table`
	OutputFirmware            outputFirmwareCmd           `cmd help:"Outputs information about the firmware and PSP/BIOS structure"`
	DumpPSPEntry              dumpPSPEntryCmd             `cmd help:"Dump an entry from PSP Directory to a file on the filesystem"`
	DumpBIOSEntry             dumpBIOSEntryCmd            `cmd help:"Dump an entry from BIOS Directory to a file on the filesystem"`
	PatchPSPEntry             patchPSPEntryCmd            `cmd help:"take a path on the filesystem pointing to a dump of an PSP entry and re-apply it to the firmware"`
	PatchBIOSEntry            patchBIOSEntryCmd           `cmd help:"take a path on the filesystem pointing to a dump of an BIOS entry and re-apply it to the firmware"`
	OutputSecurityTokensEntry outputAPCBSecurityTokensCmd `cmd help:"output security tokens of all APCB (including backup) entries in specified BIOS directory"`
}

func (s *outputFirmwareCmd) Run(ctx *context) error {
	amdFw, err := psb.ParseAMDFirmwareFile(s.FwPath)
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
	amdFw, err := psb.ParseAMDFirmwareFile(s.FwPath)
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
	directory, err := psb.DirectoryTypeFromString(v.Directory)
	if err != nil {
		return err
	}

	amdFw, err := psb.ParseAMDFirmwareFile(v.FwPath)
	if err != nil {
		return fmt.Errorf("could not parse firmware image: %w", err)
	}

	keyDB, err := psb.GetKeys(amdFw, v.KeyDBPSPLevel)
	if err != nil {
		return fmt.Errorf("could not extract keys from the firmware image: %w", err)
	}

	var pspEntryIDs []uint32
	for _, pspEntry := range v.PSPEntries {
		id, err := strconv.ParseInt(pspEntry, 16, 32)
		if err != nil {
			return fmt.Errorf("could not parse hexadecimal entry: %w", err)
		}
		pspEntryIDs = append(pspEntryIDs, uint32(id))
	}

	signatureValidations, err := psb.ValidatePSPEntries(amdFw, keyDB, directory, pspEntryIDs)
	if err != nil {
		return err
	}

	for _, validation := range signatureValidations {
		fmt.Println(validation.String())
	}
	return nil
}

func (v *validateRTMCmd) Run(ctx *context) error {
	amdFw, err := psb.ParseAMDFirmwareFile(v.FwPath)
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

func dumpHelper(fwPath string, entry string, resultFile string,
	dump func(amdFw *amd_manifest.AMDFirmware, entryID uint32, w io.Writer) (int, error),
) error {
	amdFw, err := psb.ParseAMDFirmwareFile(fwPath)
	if err != nil {
		return fmt.Errorf("could not parse firmware image: %w", err)
	}

	id, err := strconv.ParseInt(entry, 16, 32)
	if err != nil {
		return fmt.Errorf("could not parse hexadecimal entry (%s) : %w", entry, err)
	}

	f, err := os.Create(resultFile)
	if err != nil {
		return fmt.Errorf("could not create file `%s` for dumping entry %x: %w", resultFile, id, err)
	}
	defer func() {
		err := f.Close()
		if err != nil {
			fmt.Printf("could not close file %s after dumping entry %x", resultFile, id)
		}
	}()

	n, err := dump(amdFw, uint32(id), f)
	if err != nil {
		return err
	}
	fmt.Println("Entry size / Number of written bytes ", n)
	return nil
}

func (v *dumpPSPEntryCmd) Run(ctx *context) error {
	return dumpHelper(v.FwPath, v.Entry, v.EntryFile, func(amdFw *amd_manifest.AMDFirmware, entryID uint32, w io.Writer) (int, error) {
		return psb.DumpPSPEntry(amdFw, v.PSPLevel, amd_manifest.PSPDirectoryTableEntryType(entryID), w)
	})
}

func (v *dumpBIOSEntryCmd) Run(ctx *context) error {
	return dumpHelper(v.FwPath, v.Entry, v.EntryFile, func(amdFw *amd_manifest.AMDFirmware, entryID uint32, w io.Writer) (int, error) {
		return psb.DumpBIOSEntry(amdFw, v.BIOSLevel, amd_manifest.BIOSDirectoryTableEntryType(entryID), v.Instance, w)
	})
}

func patchHelper(fwPath string, entry string, entryFile string, resultFile string,
	patch func(amdFw *amd_manifest.AMDFirmware, entryID uint32, r io.Reader, w io.Writer) (int, error),
) error {
	amdFw, err := psb.ParseAMDFirmwareFile(fwPath)
	if err != nil {
		return fmt.Errorf("could not parse firmware image: %w", err)
	}

	id, err := strconv.ParseInt(entry, 16, 32)
	if err != nil {
		return fmt.Errorf("could not parse hexadecimal entry (%s) : %w", entry, err)
	}

	inFile, err := os.Open(entryFile)
	if err != nil {
		return fmt.Errorf("could not read modified entry file: %w", err)
	}
	defer func() {
		if err := inFile.Close(); err != nil {
			fmt.Printf("could not close modified entry file %s: %v", entryFile, err)
		}
	}()

	outFile, err := os.Create(resultFile)
	if err != nil {
		return fmt.Errorf("could not create file `%s` for patched firmware: %w", resultFile, err)
	}
	defer func() {
		err := outFile.Close()
		if err != nil {
			fmt.Printf("could not close file %s after dumping entry %x", resultFile, id)
		}
	}()

	n, err := patch(amdFw, uint32(id), inFile, outFile)
	if err != nil {
		return err
	}

	fmt.Println("Firmware size / Number of written bytes ", n)
	return nil
}

func (v *patchPSPEntryCmd) Run(ctx *context) error {
	return patchHelper(v.FwPath, v.Entry, v.EntryFile, v.ModifiedFirmwareFile, func(amdFw *amd_manifest.AMDFirmware, entryID uint32, r io.Reader, w io.Writer) (int, error) {
		return psb.PatchPSPEntry(amdFw, v.PSPLevel, amd_manifest.PSPDirectoryTableEntryType(entryID), r, w)
	})
}

func (v *patchBIOSEntryCmd) Run(ctx *context) error {
	return patchHelper(v.FwPath, v.Entry, v.EntryFile, v.ModifiedFirmwareFile, func(amdFw *amd_manifest.AMDFirmware, entryID uint32, r io.Reader, w io.Writer) (int, error) {
		return psb.PatchBIOSEntry(amdFw, v.BIOSLevel, amd_manifest.BIOSDirectoryTableEntryType(entryID), v.Instance, r, w)
	})
}

func (v *outputAPCBSecurityTokensCmd) Run(ctx *context) error {
	amdFw, err := psb.ParseAMDFirmwareFile(v.FwPath)
	if err != nil {
		return fmt.Errorf("could not parse firmware image: %w", err)
	}
	apcbEntries, err := psb.GetBIOSEntries(amdFw.PSPFirmware(), v.BIOSLevel, amd_manifest.APCBDataEntry)
	if err != nil {
		return fmt.Errorf("failed to get APCB binary entries: %w", err)
	}
	apcbBackupEntries, err := psb.GetBIOSEntries(amdFw.PSPFirmware(), v.BIOSLevel, amd_manifest.APCBDataBackupEntry)
	if err != nil {
		return fmt.Errorf("failed to get APCB backup binary entries: %w", err)
	}
	apcbEntries = append(apcbEntries, apcbBackupEntries...)

	for _, entry := range apcbEntries {
		data, err := psb.GetRangeBytes(amdFw.Firmware().ImageBytes(), entry.SourceAddress, uint64(entry.Size))
		if err != nil {
			return fmt.Errorf("failed to get bytes of entry %s, instance id: %d", psb.BIOSEntryType(entry.Type), entry.Instance)
		}
		tokens, err := apcb.ParseAPCBBinaryTokens(data)
		if err != nil {
			return fmt.Errorf("failed to get tokens of entry %s, instance id: %d", psb.BIOSEntryType(entry.Type), entry.Instance)
		}
		for _, token := range tokens {
			switch token.ID {
			case apcb.TokenIDPSPMeasureConfig:
			case apcb.TokenIDPSPEnableDebugMode:
			case apcb.TokenIDPSPErrorDisplay:
			case apcb.TokenIDPSPStopOnError:
			default:
				continue
			}

			tokenID := apcb.GetTokenIDString(token.ID)
			if len(tokenID) == 0 {
				tokenID = fmt.Sprintf("0x%X", token.ID)
			}

			fmt.Println("============")
			fmt.Printf("Token ID: %s\n", tokenID)
			fmt.Printf("Priority Mask: %s\n", token.PriorityMask)
			fmt.Printf("Board Mask: 0x%X\n", token.BoardMask)
			fmt.Printf("Value: 0x%X\n", token.NumValue())
			fmt.Println("============")
		}
	}
	return nil
}
