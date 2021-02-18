package txt

import (
	"fmt"
	"io"

	tools "github.com/9elements/converged-security-suite/v2/pkg/tools"
	tpm2 "github.com/google/go-tpm/tpm2"
)

func printNVIndex(nv tpm2.NVPublic) {
	fmt.Printf("   Index: 0x%x\n", nv.NVIndex)
	fmt.Printf("   Attributes: %s\n", nv.Attributes.String())
	fmt.Printf("   Size: %d\n", nv.DataSize)
	fmt.Printf("   AuthPolicy: 0x%x\n", nv.AuthPolicy)
	fmt.Println()
}

// PrintProvisioningTPM20 outputs PS and AUX index on console for TPM 2.0
func PrintProvisioningTPM20(rw io.ReadWriter) {
	fmt.Println("NV index overview")
	fmt.Println()
	ps, psErr := tpm2.NVReadPublic(rw, tpm2PSNVIndex)
	if psErr == nil {
		fmt.Println("PS NV index")
		printNVIndex(ps)
	}
	aux, err := tpm2.NVReadPublic(rw, tpm2AUXNVIndex)
	if err == nil {
		fmt.Println("AUX NV index")
		printNVIndex(aux)
	}
	fmt.Println("PS index LCP Policy")
	lcp, err := tpm2.NVRead(rw, tpm2PSNVIndex)
	if err == nil && psErr == nil {
		lcp, lcp2, err := tools.ParsePolicy(lcp)
		if err == nil {
			if lcp != nil {
				fmt.Println("Not implemented yet")
				return
			}
			if lcp2 != nil {
				lcp2.PrettyPrint()
				return
			}
		}
	}
	fmt.Println("Couldn't read/parse LCP config from NVRAM")
}

// PrintProvisioningTPM12 outputs PS and AUX index on console for TPM 1.2
func PrintProvisioningTPM12(rw io.ReadWriter) {
	fmt.Println("Not implemented yet")
}
