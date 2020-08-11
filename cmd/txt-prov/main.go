package main

import (
	"flag"
	"fmt"
	"os"

	prov "github.com/9elements/converged-security-suite/pkg/provisioning"
	tss "github.com/9elements/go-tss"
)

func main() {
	flag.Parse()
	err := run()
	if err != nil {
		fmt.Printf("%v\n", err)
		os.Exit(1)
	}
}

func run() error {
	var err error
	var delHash, writeHash *[32]byte
	if *help {
		showHelp()
		return nil
	}
	if *version {
		showVersion()
		return nil
	}

	tpmCon, err := tss.NewTPM()
	if err != nil {
		return err
	}
	defer tpmCon.Close()

	switch tpmCon.Version {
	case tss.TPMVersion12:
		// Uses SHA1,
		if *tpm == "tpm20" {
			return fmt.Errorf("TPM2.0 selected, but system has TPM1.2. TPM1.2 not supported")
		}
		return fmt.Errorf("TPM 1.2 not supported yet")
	case tss.TPMVersion20:
		// Uses SHA256

		if *tpm == "tpm12" {
			return fmt.Errorf("TPM12 selected, but system has TPM2.0")
		}
		if *loadfiles {
			delHash, writeHash, _, err = loadFilesSHA256()
			if err != nil {
				return err
			}
		} else {
			delHash, writeHash, err = handlePasswordsTPM20()
			if err != nil {
				return err
			}
			if *savePol {
				if err := writeFile("delHash", *delHash); err != nil {
					return err
				}
				if err = writeFile("writeHash", *writeHash); err != nil {
					return err
				}
			}
		}

		if !*deletePS && !*deleteAUX && *provi {
			lcppol, err := getLCPDataFromFile()
			if err != nil {
				return err
			}
			psHash, err := prov.ProvisionTPM20(tpmCon.RWC, delHash[:32], writeHash[:32], lcppol)
			if err != nil {
				return fmt.Errorf("ProvisionTPM20() failed: %v", err)
			}
			if *savePol {
				if err := writeFile("psPolicy", *psHash); err != nil {
					return err
				}
			}

		}
		if *deletePS && !*deleteAUX && !*provi && delHash != nil && writeHash != nil {

			return prov.DeletePSindexTPM20(tpmCon.RWC, delHash[:32], writeHash[:32])
		}
		if !*deletePS && *deleteAUX && !*provi && writeHash != nil && delHash != nil {
			lcppol, err := getLCPDataFromFile()
			if err != nil {
				return err
			}
			return prov.DeleteAUXindexTPM20(tpmCon.RWC, lcppol, delHash[:32], writeHash[:32])

		}
		if *deletePS && *deleteAUX {
			return fmt.Errorf("Using -dAux and -dPS is not permitted")
		}
		return nil
	}
	return fmt.Errorf("No TPM device found")
}
