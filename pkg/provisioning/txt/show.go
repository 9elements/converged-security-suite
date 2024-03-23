package txt

import (
	"fmt"
	"io"

	tools "github.com/9elements/converged-security-suite/v2/pkg/tools"
	tpm2 "github.com/google/go-tpm/tpm2"
	log "github.com/sirupsen/logrus"
)

func printNVIndex(nv tpm2.NVPublic) {
	var s string
	s += fmt.Sprintf("   Index: 0x%x\n", nv.NVIndex)
	s += fmt.Sprintf("   Attributes: %s\n", nv.Attributes.String())
	s += fmt.Sprintf("   Size: %d\n", nv.DataSize)
	s += fmt.Sprintf("   AuthPolicy: 0x%x\n", nv.AuthPolicy)
	log.Info(s)
}

// PrintProvisioningTPM20 outputs PS and AUX index on console for TPM 2.0
func PrintProvisioningTPM20(rw io.ReadWriter) {
	log.Info("NV index overview")
	log.Info("")
	ps, psErr := tpm2.NVReadPublic(rw, tpm2PSNVIndex)
	if psErr == nil {
		log.Info("PS NV index")
		printNVIndex(ps)
	}
	aux, err := tpm2.NVReadPublic(rw, tpm2AUXNVIndex)
	if err == nil {
		log.Info("AUX NV index")
		printNVIndex(aux)
	}
	log.Info("PS index LCP Policy")
	lcp, err := tpm2.NVRead(rw, tpm2PSNVIndex)
	if err == nil && psErr == nil {
		lcp, lcp2, err := tools.ParsePolicy(lcp)
		if err == nil {
			if lcp != nil {
				log.Error("Not implemented yet")
				return
			}
			if lcp2 != nil {
				lcp2.PrettyPrint()
				return
			}
		}
	}
	log.Error("Couldn't read/parse LCP config from NVRAM")
}

// PrintProvisioningTPM12 outputs PS and AUX index on console for TPM 1.2
func PrintProvisioningTPM12(rw io.ReadWriter) {
	log.Error("Not implemented yet")
}
