package main

import (
	"flag"
	"fmt"
	"io"

	"github.com/9elements/converged-security-suite/v2/pkg/provisioning"
	"github.com/9elements/converged-security-suite/v2/pkg/tools"
)

var (
	// Flags
	auxDelete    = flag.Bool("adel", false, "Delete AUX index if exists in TPM NVRAM")
	auxDefine    = flag.Bool("adef", false, "Define AUX index if not exists in TPM NVRAM")
	psDefine     = flag.Bool("pdef", false, "Define PS index if not exists in TPM NVRAM")
	psDelete     = flag.Bool("pdel", false, "Delete PS index if exists in TPM NVRAM")
	psUpdate     = flag.Bool("pup", false, "Update PS index content in TPM NVRAM")
	platformProv = flag.Bool("pp", false, "Provision PS & AUX index with LCP config")
	show         = flag.Bool("show", false, "Shows current provisioned PS & AUX index in NVRAM on stdout")
	config       = flag.String("config", "lcp.json", "Provide a json filename with LCP configuration. Default: lcp.json")
	output       = flag.String("out", "", "Stores written binary PS index LCP policy into file")
	version      = flag.Bool("v", false, "Shows version and license information")
)

func provisionTPM20(rw io.ReadWriter, passHash []byte, lcpPolilcy *tools.LCPPolicy2) error {
	passHash, err := readPassphraseHashTPM20()
	if err != nil {
		return err
	}
	if err := provisioning.DefinePSIndexTPM20(rw, passHash); err != nil {
		return fmt.Errorf("definePSIndexTPM20() failed: %v", err)
	}
	if err := provisioning.WritePSIndexTPM20(rw, lcpPolilcy, passHash); err != nil {
		return fmt.Errorf("writePSPolicy() failed: %v", err)
	}
	if err := provisioning.DefineAUXIndexTPM20(rw); err != nil {
		return fmt.Errorf("defineAUXIndexTPM20() failed: %v", err)
	}
	return nil
}

func provisionTPM12(rw io.ReadWriter, lcppol *tools.LCPPolicy2) error {
	return fmt.Errorf("Not implemented yet")
}
