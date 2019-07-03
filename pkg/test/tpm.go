package test

import (
	"fmt"
	"io"

	"github.com/9elements/txt-suite/pkg/api"
	"github.com/google/go-tpm/tpm2"
)

const (
	psIndex  = 0x80000001
	auxIndex = 0x80000002
)

var (
	tpmConnection *io.ReadWriteCloser = nil
	TestsTPM                          = [...]Test{
		Test{
			name:     "TPM 1.2 present",
			required: true,
			function: Test16TPMPresent,
		},
		Test{
			name:     "TPM in production mode",
			function: Test17TPMIsLocked,
			required: true,
		},
		Test{
			name:     "PS index is set in NVRAM",
			function: Test18PSIndexIsSet,
			required: true,
		},
		Test{
			name:     "AUX index is set in NVRAM",
			function: Test19AUXIndexIsSet,
			required: true,
		},
		Test{
			name:     "PS index contains a valid LCP Policy",
			function: Test20LCPPolicyIsValid,
			required: true,
		},
	}
)

// Connects to a TPM device (virtual or real) at the given path
func ConnectTPM(tpmPath string) error {
	conn, err := tpm2.OpenTPM(tpmPath)
	if err != nil {
		return err
	}

	tpmConnection = &conn
	return nil
}

// Checks whether a TPM is present and answers to GetCapability
func Test16TPMPresent() (bool, error) {
	if tpmConnection == nil {
		return false, fmt.Errorf("No TPM connection")
	}

	ca, _, err := tpm2.GetCapability(*tpmConnection, tpm2.CapabilityTPMProperties, 1, uint32(tpm2.Manufacturer))

	return ca != nil && err == nil, nil
}

// TPM is not in manufacturing mode
func Test17TPMIsLocked() (bool, error) {
	return false, fmt.Errorf("Unimplmented")
}

// TPM NV ram has a valid PS index
func Test18PSIndexIsSet() (bool, error) {
	if tpmConnection == nil {
		return false, fmt.Errorf("Not connected to TPM")
	}
	meta, err := tpm2.NVReadPublic(*tpmConnection, psIndex)
	if err != nil {
		return false, err
	}

	rc := true
	rc = rc && meta.NVIndex == psIndex
	rc = rc && (meta.Attributes&tpm2.KeyProp(tpm2.AttrWriteLocked) != 0)

	return rc, nil
}

// TPM NV ram has a valid AUX index
func Test19AUXIndexIsSet() (bool, error) {
	if tpmConnection == nil {
		return false, fmt.Errorf("Not connected to TPM")
	}
	meta, err := tpm2.NVReadPublic(*tpmConnection, auxIndex)
	if err != nil {
		return false, err
	}

	rc := true
	rc = rc && meta.NVIndex == auxIndex

	return rc, nil
}

// PS index contains a valid LCP policy
func Test20LCPPolicyIsValid() (bool, error) {
	if tpmConnection == nil {
		return false, fmt.Errorf("Not connected to TPM")
	}
	data, err := tpm2.NVRead(*tpmConnection, psIndex)
	if err != nil {
		return false, err
	}

	lcp, err := api.ParsePolicy(data)
	if err != nil {
		return false, err
	}

	return lcp.Version == 0x100, nil
}

// Reads PCR-00 and checks whether if it's not the EmptyDigest
func Test21PCR0IsSet() (bool, error) {
	if tpmConnection == nil {
		return false, fmt.Errorf("Not connected to TPM")
	}
	ca, _, err := tpm2.GetCapability(*tpmConnection, tpm2.CapabilityPCRs, 1, 0)
	if ca == nil || err != nil {
		return false, err
	}

	for i := 0; i < 4; i++ {
		pcr, _ := tpm2.ReadPCRs(*tpmConnection, ca[i].(tpm2.PCRSelection))
		for j := 0; j < len(pcr[0]); j++ {
			if pcr[0][j] != 0 {
				return false, nil
			}
		}
	}

	return true, nil
}

// RunTests just for debugging purposes
func RunTPMTests() (bool, error) {
	err := connectTPM("/dev/tpm0")
	if err != nil {
		return false, err
	}

	rc, err := Test16TPMPresent()
	if err != nil {
		fmt.Printf("ERROR\n\t%s\n", err)
		return false, nil
	}
	if rc {
		fmt.Println("OK")
	} else {
		fmt.Println("FAIL\n\tNo TPM found")
		return false, nil
	}

	rc, err = Test17TPMIsLocked()
	if err != nil {
		fmt.Printf("ERROR\n\t%s\n", err)
		return false, nil
	}
	if rc {
		fmt.Println("OK")
	} else {
		fmt.Println("FAIL\n\tTPM is in manufacturing mode")
		return false, nil
	}

	rc, err = Test18PSIndexIsSet()
	if err != nil {
		fmt.Printf("ERROR\n\t%s\n", err)
		return false, nil
	}
	if rc {
		fmt.Println("OK")
	} else {
		fmt.Println("FAIL\n\tTPM is in manufacturing mode")
		return false, nil
	}

	rc, err = Test19AUXIndexIsSet()
	if err != nil {
		fmt.Printf("ERROR\n\t%s\n", err)
		return false, nil
	}
	if rc {
		fmt.Println("OK")
	} else {
		fmt.Println("FAIL\n\tTPM is in manufacturing mode")
		return false, nil
	}

	rc, err = Test20LCPPolicyIsValid()
	if err != nil {
		fmt.Printf("ERROR\n\t%s\n", err)
		return false, nil
	}
	if rc {
		fmt.Println("OK")
	} else {
		fmt.Println("FAIL\n\tTPM is in manufacturing mode")
		return false, nil
	}

	tpmConnection = nil

	return true, nil
}
