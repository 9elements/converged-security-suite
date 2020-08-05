package main

import (
	"crypto"
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
	var delHash, writeHash []byte
	var hA *crypto.Hash
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
		// Only uses SHA1, so we don't need -t evaluation
		return fmt.Errorf("TPM 1.2 not supported yet")
	case tss.TPMVersion20:
		// Uses SHA1,SHA256, SHA384, SHA512

		if *loadfiles {
			delHash, writeHash, _, hA, err = loadFiles()
			if err != nil {
				return err
			}
		} else {
			hA, err := deconstructHashesAlg()
			if err != nil {
				return err
			}
			delHash, writeHash, err = handlePasswordsTPM20(*hA)
			if err != nil {
				return err
			}
			if *savePol == true {
				if err := writeFile("delHash", delHash, *hA); err != nil {
					return err
				}
				if err = writeFile("writeHash", writeHash, *hA); err != nil {
					return err
				}
			}
		}

		if !*deletePS && !*deleteAUX && *provi {
			psHash, hashAlg, err := prov.ProvisionTPM20(tpmCon.RWC, delHash, writeHash, *hA)
			if err != nil {
				return err
			}
			if *savePol == true {
				if err := writeFile("psPolicy", psHash, *hashAlg); err != nil {
					return err
				}
			}

		}
		if *deletePS && !*deleteAUX && !*provi && delHash != nil {
			return prov.DeletePSindexTPM20(tpmCon.RWC, delHash)
		}
		if !*deletePS && *deleteAUX && !*provi && writeHash != nil {
			return prov.DeleteAUXindexTPM20(tpmCon.RWC, writeHash)

		}
		if *deletePS && *deleteAUX {
			return fmt.Errorf("Using -dAux and -dPS is not permitted")
		}
	}
	return fmt.Errorf("No TPM device found")
}
