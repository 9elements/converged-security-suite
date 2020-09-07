package main

import (
	"fmt"
	"io"

	"github.com/9elements/converged-security-suite/v2/pkg/hwapi"

	"github.com/9elements/converged-security-suite/v2/pkg/provisioning/txt"
	"github.com/9elements/converged-security-suite/v2/pkg/tools"
)

// Context for kong command line parser
// We need a TPM device in most commands.
type context struct {
	debug bool
}

type versionCmd struct {
}

type auxDeleteCmd struct {
	Config string `arg required name:"config" default:"lcp.config" help:"Filename of LCP config file in JSON format"`
	Out    string `flag optional name:"out" help:"Filename to write binary PS index LCP Policy into"`
}

type auxDefineCmd struct {
}

type psDeleteCmd struct {
}
type psDefineCmd struct {
}
type psUpdateCmd struct {
	Config string `arg required name:"config" default:"lcp.config" help:"Filename of LCP config file in JSON format" type:"path"`
	Out    string `flag optional name:"output" help:"Filename to write binary PS index LCP Policy into" type:"path"`
}
type platProvCmd struct {
	Config string `arg required name:"config" default:"lcp.config" help:"Filename of LCP config file in JSON format" type:"path"`
	Out    string `flag optional name:"output" help:"Filename to write binary PS index LCP Policy into" type:"path"`
}
type showCmd struct {
}

var cli struct {
	Debug                    bool `help:"Enable debug mode"`
	ManifestStrictOrderCheck bool `help:"Enable checking of manifest elements order"`

	Version      versionCmd   `cmd help:"Prints the version of the program"`
	AuxDelete    auxDeleteCmd `cmd help:"Delete AUX index if exists in TPM NVRAM"`
	AuxDefine    auxDefineCmd `cmd help:"Define AUX index if not exists in TPM NVRAM"`
	PsDelete     psDeleteCmd  `cmd help:"Delete PS index if exists in TPM NVRAM"`
	PsDefine     psDefineCmd  `cmd help:"Define PS index if not exists in TPM NVRAM"`
	PsUpdate     psUpdateCmd  `cmd help:"Update PS index content in TPM NVRAM"`
	PlatformProv platProvCmd  `cmd help:"Provision PS & AUX index with LCP config"`
	Show         showCmd      `cmd help:"Show current provisioned PS & AUX index in NVRAM on stdout"`
}

func (v *versionCmd) Run(ctx *context) error {
	tools.ShowVersion(programName, gittag, gitcommit)
	return nil
}

func (a *auxDeleteCmd) Run(ctx *context) error {
	// Set Aux Delete bit in LCP Policy and writes it to PS index in TPM NVRAM
	tpm, err := hwapi.NewTPM()
	if err != nil {
		return err
	}
	defer tpm.Close()

	switch tpm.Version {
	case hwapi.TPMVersion12:
		return fmt.Errorf("TPM 1.2 not supported yet")
	case hwapi.TPMVersion20:
		lcp, err := loadConfig(a.Config)
		if err != nil {
			return fmt.Errorf("Couldn't parse LCP config file: %v", err)
		}
		passHash, err := readPassphraseHashTPM20()
		if err != nil {
			return fmt.Errorf("Couldn't read password from stdin: %v", err)
		}
		if err = txt.DeleteAUXindexTPM20(tpm.RWC, lcp, passHash); err != nil {
			return fmt.Errorf("Couldn't delete AUX index: %v", err)
		}
		if len(a.Out) > 0 {
			if err = writePSPolicy2file(lcp, a.Out); err != nil {
				return fmt.Errorf("Couldn't write PS Policy2 into file: %v", err)
			}
		}
	default:
		return fmt.Errorf("TPM device not recognized")
	}
	return nil
}

func (a *auxDefineCmd) Run(ctx *context) error {
	// Define AUX index in TPM NVRAM
	tpm, err := hwapi.NewTPM()
	if err != nil {
		return err
	}
	switch tpm.Version {
	case hwapi.TPMVersion12:
		return fmt.Errorf("TPM 1.2 not supported yet")
	case hwapi.TPMVersion20:
		lock, err := IsNVRAMUnlocked(tpm)
		if err != nil {
			return fmt.Errorf("Couldn't check if NVRAM is unlocked: %v", err)
		}
		if lock {
			return fmt.Errorf("NVRAM is locked, please disable Intel TXT or any firmware TPM driver")
		}
		if err = txt.DefineAUXIndexTPM20(tpm.RWC); err != nil {
			return fmt.Errorf("Couldn't define AUX index: %v", err)
		}
	default:
		return fmt.Errorf("TPM device not recognized")
	}
	return nil
}
func (p *psDeleteCmd) Run(ctx *context) error {
	// Delete PS index in TPM NVRAM
	tpm, err := hwapi.NewTPM()
	if err != nil {
		return err
	}
	switch tpm.Version {
	case hwapi.TPMVersion12:
		return fmt.Errorf("TPM 1.2 not supported yet")
	case hwapi.TPMVersion20:
		passHash, err := readPassphraseHashTPM20()
		if err != nil {
			return fmt.Errorf("Couldn't read password from stdin: %v", err)
		}
		if err = txt.DeletePSIndexTPM20(tpm.RWC, passHash); err != nil {
			return fmt.Errorf("Couldn't delete PS index: %v", err)
		}
	default:
		return fmt.Errorf("TPM device not recognized")
	}
	return nil
}
func (p *psDefineCmd) Run(ctx *context) error {
	// Define PS index in TPM NVRAM
	tpm, err := hwapi.NewTPM()
	if err != nil {
		return err
	}
	switch tpm.Version {
	case hwapi.TPMVersion12:
		return fmt.Errorf("TPM 1.2 not supported yet")
	case hwapi.TPMVersion20:
		lock, err := IsNVRAMUnlocked(tpm)
		if err != nil {
			return fmt.Errorf("Couldn't check if NVRAM is unlocked: %v", err)
		}
		if lock {
			return fmt.Errorf("NVRAM is locked, please disable Intel TXT or any firmware TPM driver")
		}
		passHash, err := readPassphraseHashTPM20()
		if err != nil {
			return fmt.Errorf("Couldn't read password from stdin: %v", err)
		}
		if err = txt.DefinePSIndexTPM20(tpm.RWC, passHash); err != nil {
			fmt.Errorf("Couldn't define PS index: %v", err)
		}
	default:
		return fmt.Errorf("TPM device not recognized")
	}
	return nil
}
func (p *psUpdateCmd) Run(ctx *context) error {
	// Writes new LCP Policy to PS index in TPM NVRAM
	tpm, err := hwapi.NewTPM()
	if err != nil {
		return err
	}
	switch tpm.Version {
	case hwapi.TPMVersion12:
		return fmt.Errorf("TPM 1.2 not supported yet")
	case hwapi.TPMVersion20:
		lcp, err := loadConfig(p.Config)
		if err != nil {
			return fmt.Errorf("Couldn't parse LCP config file: %v", err)
		}
		passHash, err := readPassphraseHashTPM20()
		if err != nil {
			return fmt.Errorf("Couldn't read password from stdin: %v", err)
		}
		if err = txt.WritePSIndexTPM20(tpm.RWC, lcp, passHash); err != nil {
			return fmt.Errorf("Couldn't update PS index: %v", err)
		}
		if len(p.Out) > 0 {
			if err = writePSPolicy2file(lcp, p.Out); err != nil {
				return fmt.Errorf("Couldn't write PS Policy2 into file: %v", err)
			}
		}
	default:
		return fmt.Errorf("TPM device not recognized")
	}
	return nil
}
func (p *platProvCmd) Run(ctx *context) error {
	// Provision PS & AUX index in TPM NVRAM with LCP Policy
	tpm, err := hwapi.NewTPM()
	if err != nil {
		return err
	}
	switch tpm.Version {
	case hwapi.TPMVersion12:
		return fmt.Errorf("TPM 1.2 not supported yet")
	case hwapi.TPMVersion20:
		lock, err := IsNVRAMUnlocked(tpm)
		if err != nil {
			return fmt.Errorf("Couldn't check if NVRAM is unlocked: %v", err)
		}
		if lock {
			return fmt.Errorf("NVRAM is locked, please disable Intel TXT or any firmware TPM driver")
		}
		lcp, err := loadConfig(p.Config)
		if err != nil {
			return fmt.Errorf("Couldn't parse LCP config file: %v", err)
		}
		passHash, err := readPassphraseHashTPM20()
		if err != nil {
			return fmt.Errorf("Couldn't read password from stdin: %v", err)
		}
		if err = provisionTPM20(tpm.RWC, passHash, lcp); err != nil {
			return fmt.Errorf("Couldn't provision PS & AUX index: %v", err)
		}
		if len(p.Out) > 0 {
			if err = writePSPolicy2file(lcp, p.Out); err != nil {
				fmt.Printf("Couldn't write PS Policy2 into file: %v\n", err)
			}
		}
	default:
		return fmt.Errorf("TPM device not recognized")
	}
	return nil
}
func (s *showCmd) Run(ctx *context) error {
	// Show PS & AUX index content from TPM NVRAM
	tpm, err := hwapi.NewTPM()
	if err != nil {
		return err
	}
	switch tpm.Version {
	case hwapi.TPMVersion12:
		return fmt.Errorf("TPM 1.2 not supported yet")
	case hwapi.TPMVersion20:
		txt.PrintProvisioningTPM20(tpm.RWC)
	default:
		return fmt.Errorf("TPM device not recognized")
	}
	return nil
}

func provisionTPM20(rw io.ReadWriter, passHash []byte, lcpPolilcy *tools.LCPPolicy2) error {
	passHash, err := readPassphraseHashTPM20()
	if err != nil {
		return err
	}
	if err := txt.DefinePSIndexTPM20(rw, passHash); err != nil {
		return fmt.Errorf("definePSIndexTPM20() failed: %v", err)
	}
	if err := txt.WritePSIndexTPM20(rw, lcpPolilcy, passHash); err != nil {
		return fmt.Errorf("writePSPolicy() failed: %v", err)
	}
	if err := txt.DefineAUXIndexTPM20(rw); err != nil {
		return fmt.Errorf("defineAUXIndexTPM20() failed: %v", err)
	}
	return nil
}

func provisionTPM12(rw io.ReadWriter, lcppol *tools.LCPPolicy2) error {
	return fmt.Errorf("Not implemented yet")
}
