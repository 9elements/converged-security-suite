package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/9elements/converged-security-suite/pkg/provisioning"
	"github.com/9elements/converged-security-suite/pkg/tools"
	tss "github.com/9elements/go-tss"
)

const programName = "Intel TXT Provisioning tool"

var (
	gitcommit string
	gittag    string
)

func main() {
	flag.Parse()
	if *version {
		tools.ShowVersion(programName, gittag, gitcommit)
		os.Exit(0)
	}
	tpmTss, err := tss.NewTPM()
	if err != nil {
		fmt.Printf("Couldn't set up tpm connection: %v\n", err)
		os.Exit(1)
	}
	defer tpmTss.Close()

	switch tpmTss.Version {
	case tss.TPMVersion12:
		fmt.Println("TPM 1.2 not supported yet")
		os.Exit(1)
	case tss.TPMVersion20:
		if *auxDelete {
			lcp, err := loadConfig(*config)
			if err != nil {
				fmt.Printf("Couldn't parse LCP config file: %v\n", err)
				os.Exit(1)
			}
			passHash, err := readPassphraseHashTPM20()
			if err != nil {
				fmt.Printf("Couldn't read password from stdin: %v\n", err)
				os.Exit(1)
			}
			if err = provisioning.DeleteAUXindexTPM20(tpmTss.RWC, lcp, passHash); err != nil {
				fmt.Printf("Couldn't delete AUX index: %v\n", err)
				os.Exit(1)
			}
			if len(*output) > 0 {
				if err = writePSPolicy2file(lcp, *output); err != nil {
					fmt.Printf("Couldn't write PS Policy2 into file: %v\n", err)
				}
			}
		} else if *auxDefine {
			lock, err := IsNVRAMUnlocked(tpmTss)
			if err != nil {
				fmt.Printf("Couldn't check if NVRAM is unlocked: %v\n", err)
				os.Exit(1)
			}
			if lock {
				fmt.Println("NVRAM is locked, please disable Intel TXT or any firmware TPM driver")
				os.Exit(1)
			}
			if err = provisioning.DefineAUXIndexTPM20(tpmTss.RWC); err != nil {
				fmt.Printf("Couldn't define AUX index: %v\n", err)
				os.Exit(1)
			}
		} else if *psDefine {
			lock, err := IsNVRAMUnlocked(tpmTss)
			if err != nil {
				fmt.Printf("Couldn't check if NVRAM is unlocked: %v\n", err)
				os.Exit(1)
			}
			if lock {
				fmt.Println("NVRAM is locked, please disable Intel TXT or any firmware TPM driver")
				os.Exit(1)
			}
			passHash, err := readPassphraseHashTPM20()
			if err != nil {
				fmt.Printf("Couldn't read password from stdin: %v\n", err)
				os.Exit(1)
			}
			if err = provisioning.DefinePSIndexTPM20(tpmTss.RWC, passHash); err != nil {
				fmt.Printf("Couldn't define PS index: %v\n", err)
				os.Exit(1)
			}
		} else if *psDelete {
			passHash, err := readPassphraseHashTPM20()
			if err != nil {
				fmt.Printf("Couldn't read password from stdin: %v\n", err)
				os.Exit(1)
			}
			if err = provisioning.DeletePSIndexTPM20(tpmTss.RWC, passHash); err != nil {
				fmt.Printf("Couldn't delete PS index: %v\n", err)
				os.Exit(1)
			}
		} else if *psUpdate {
			lcp, err := loadConfig(*config)
			if err != nil {
				fmt.Printf("Couldn't parse LCP config file: %v\n", err)
				os.Exit(1)
			}
			passHash, err := readPassphraseHashTPM20()
			if err != nil {
				fmt.Printf("Couldn't read password from stdin: %v\n", err)
				os.Exit(1)
			}
			if err = provisioning.WritePSIndexTPM20(tpmTss.RWC, lcp, passHash); err != nil {
				fmt.Printf("Couldn't update PS index: %v\n", err)
				os.Exit(1)
			}
			if len(*output) > 0 {
				if err = writePSPolicy2file(lcp, *output); err != nil {
					fmt.Printf("Couldn't write PS Policy2 into file: %v\n", err)
				}
			}
		} else if *platformProv {
			lock, err := IsNVRAMUnlocked(tpmTss)
			if err != nil {
				fmt.Printf("Couldn't check if NVRAM is unlocked: %v\n", err)
				os.Exit(1)
			}
			if lock {
				fmt.Println("NVRAM is locked, please disable Intel TXT or any firmware TPM driver")
				os.Exit(1)
			}
			lcp, err := loadConfig(*config)
			if err != nil {
				fmt.Printf("Couldn't parse LCP config file: %v\n", err)
				os.Exit(1)
			}
			passHash, err := readPassphraseHashTPM20()
			if err != nil {
				fmt.Printf("Couldn't read password from stdin: %v\n", err)
				os.Exit(1)
			}
			if err = provisionTPM20(tpmTss.RWC, passHash, lcp); err != nil {
				fmt.Printf("Couldn't provision PS & AUX index: %v\n", err)
				os.Exit(1)
			}
			if len(*output) > 0 {
				if err = writePSPolicy2file(lcp, *output); err != nil {
					fmt.Printf("Couldn't write PS Policy2 into file: %v\n", err)
				}
			}
		} else if *show {
			provisioning.PrintProvisioningTPM20(tpmTss.RWC)
		}
	default:
		fmt.Println("No TPM device found")
		os.Exit(1)
	}
	return
}
