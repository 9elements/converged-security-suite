package test

import (
	"fmt"
	"io"

	"github.com/google/go-tpm/tpm2"
)

var tpmcon io.ReadWriteCloser
var err error

// ConnectTpm connects to a TPM-Device (virtual or real), just give path
func ConnectTpm(tpmPath string) {
	tpmcon, err = tpm2.OpenTPM(tpmPath)
	if err != nil {
		fmt.Println("Can't open TPM %q: %v", tpmPath, err)
	}
}

// CloseTpm close a existing connection
func CloseTpm() bool {
	if err := tpmcon.Close(); err != nil {
		fmt.Println("Can't close TPM: %v", err)
		return false
	}
	return true
}

// TPMPresent checks if a TPM is present and answers to a booty-call
func TPMPresent() bool {
	state := false
	if tpmcon != nil {
		recInterf, _, _ := tpm2.GetCapability(tpmcon, tpm2.CapabilityTPMProperties, 1, uint32(tpm2.Manufacturer))
		if recInterf != nil {
			if recInterf[0].(tpm2.TaggedProperty).Value != 0 {
				state = true
			}

		}
	}
	return state
}

// TPMReadPCR0 reads if PCR0-Registers have been written
func TPMReadPCR0() bool {
	state := false
	tpm2.Startup(tpmcon, tpm2.StartupClear)
	if tpmcon != nil {
		recInterf, _, err := tpm2.GetCapability(tpmcon, tpm2.CapabilityPCRs, 1, 0)
		if recInterf == nil {
			fmt.Printf("%s", err)
			return state
		}

		for i := 0; i < 4; i++ {
			pcr, _ := tpm2.ReadPCRs(tpmcon, recInterf[i].(tpm2.PCRSelection))
			for j := 0; j < len(pcr[0]); j++ {
				if pcr[0][j] != 0 {
					state = true
				}
			}
		}
	}
	return state
}

// RunTests just for debugging purposes
func RunTPMTests() {
	ConnectTpm("/dev/tpm2")
	fmt.Printf("%+v", TPMPresent())
	fmt.Printf("%+v", TPMReadPCR0())
	CloseTpm()
}
