package test

import (
		"fmt"
		"github.com/google/go-tpm/tpm2"
	)
//	Test if TPM-Module is responding or not.
func TPMPresent(tpmPath string) bool {
	//connect to TPM
	rwc, err := tpm2.OpenTPM(tpmPath)
	if err != nil {
		fmt.Println("Can't open TPM %q: %v", tpmPath, err)
		return false
	}
	defer func() {
		if err := rwc.Close(); err != nil {
			fmt.Println("Can't close TPM %q: %v", tpmPath, err)
		}
	}()
	//Retrieve information with GetCapability
	recInterf, _, err := tpm2.GetCapability(rwc,tpm2.CapabilityTPMProperties,1,uint32(tpm2.PTManufacturer))

	if err != nil {
		fmt.Println("%v", err)
		return false
	}

	if recInterf != nil {
		fmt.Println("Interfaces vorhanden")
		fmt.Printf("%x\n", recInterf[0].(tpm2.TaggedProperty).Value)
		return true
	}
	return false
}
