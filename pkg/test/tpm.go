package test

import (
	"bytes"
	"fmt"
	"io"

	tpm1 "github.com/google/go-tpm/tpm"
	"github.com/google/go-tpm/tpm2"

	"github.com/9elements/txt-suite/pkg/api"
)

const (
	psIndex  = 0x50000001
	auxIndex = 0x50000003
)

var (
	tpm12Connection *io.ReadWriteCloser = nil
	tpm20Connection *io.ReadWriteCloser = nil
	TestsTPM                            = [...]Test{
		Test{
			Name:     "TPM 1.2 present",
			Required: true,
			function: Test16TPMPresent,
		},
		Test{
			Name:     "TPM in production mode",
			function: Test17TPMIsLocked,
			Required: false,
		},
		Test{
			Name:     "PS index is set in NVRAM",
			function: Test18PSIndexIsSet,
			Required: true,
		},
		Test{
			Name:     "AUX index is set in NVRAM",
			function: Test19AUXIndexIsSet,
			Required: true,
		},
		Test{
			Name:     "PS index contains a valid LCP Policy",
			function: Test20LCPPolicyIsValid,
			Required: true,
		},
	}
)

// Connects to a TPM device (virtual or real) at the given path
func ConnectTPM(tpmPath string) error {
	conn, err := tpm2.OpenTPM(tpmPath)
	if err != nil {
		conn, err = tpm1.OpenTPM(tpmPath)

		if err != nil {
			return err
		}

		tpm12Connection = &conn
		return nil
	}

	tpm20Connection = &conn
	return nil
}

// Checks whether a TPM is present and answers to GetCapability
func Test16TPMPresent() (bool, error) {
	if tpm12Connection != nil {
		vid, err := tpm1.GetManufacturer(*tpm12Connection)

		return vid != nil && err == nil, nil
	} else if tpm20Connection != nil {
		ca, _, err := tpm2.GetCapability(*tpm20Connection, tpm2.CapabilityTPMProperties, 1, uint32(tpm2.Manufacturer))

		return ca != nil && err == nil, nil
	} else {
		return false, fmt.Errorf("No TPM connection")
	}
}

// TPM NVRAM is locked
func Test17TPMIsLocked() (bool, error) {
	if tpm12Connection != nil {
		flags, err := tpm1.GetPermanentFlags(*tpm12Connection)

		return flags.NvLocked, err
	} else if tpm20Connection != nil {
		return false, fmt.Errorf("Unimplemented: TPM 2.0")
	} else {
		return false, fmt.Errorf("No TPM connection")
	}
}

// TPM NVRAM has a valid PS index
func Test18PSIndexIsSet() (bool, error) {
	if tpm12Connection != nil {
		data, err := tpm1.NVReadValueNoAuth(*tpm12Connection, psIndex, 0, 54)
		if err != nil {
			return false, err
		}

		return len(data) == 54, err
	} else if tpm20Connection != nil {
		meta, err := tpm2.NVReadPublic(*tpm20Connection, psIndex)
		if err != nil {
			return false, err
		}

		rc := true
		rc = rc && meta.NVIndex == psIndex
		rc = rc && (meta.Attributes&tpm2.KeyProp(tpm2.AttrWriteLocked) != 0)

		return rc, nil
	} else {
		return false, fmt.Errorf("Not connected to TPM")
	}
}

// TPM NVRAM has a valid AUX index
func Test19AUXIndexIsSet() (bool, error) {
	if tpm12Connection != nil {
		buf, err := tpm1.NVReadValueNoAuth(*tpm12Connection, auxIndex, 0, 1)

		return len(buf) == 1, err
	} else if tpm20Connection != nil {
		meta, err := tpm2.NVReadPublic(*tpm20Connection, auxIndex)
		if err != nil {
			return false, err
		}

		return meta.NVIndex == auxIndex, nil
	} else {
		return false, fmt.Errorf("Not connected to TPM")
	}
}

// PS index contains a valid LCP policy
func Test20LCPPolicyIsValid() (bool, error) {
	var data []byte
	var err error

	if tpm12Connection != nil {
		data, err = tpm1.NVReadValueNoAuth(*tpm12Connection, psIndex, 0, 54)

		if err != nil {
			return false, err
		}
	} else if tpm20Connection != nil {
		data, err = tpm2.NVRead(*tpm20Connection, psIndex)

		if err != nil {
			return false, err
		}
	} else {
		return false, fmt.Errorf("Not connected to TPM")
	}

	lcp, err := api.ParsePolicy(data)
	if err != nil {
		return false, err
	}

	return lcp.Version < 0x300, nil
}

// Reads PCR-00 and checks whether if it's not the EmptyDigest
func Test21PCR0IsSet() (bool, error) {
	if tpm12Connection != nil {
		pcr, err := tpm1.ReadPCR(*tpm12Connection, 0)

		return bytes.Equal(pcr, []byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}) && err == nil, err
	} else if tpm20Connection != nil {
		ca, _, err := tpm2.GetCapability(*tpm20Connection, tpm2.CapabilityPCRs, 1, 0)
		if ca == nil || err != nil {
			return false, err
		}

		for i := 0; i < 4; i++ {
			pcr, _ := tpm2.ReadPCRs(*tpm20Connection, ca[i].(tpm2.PCRSelection))
			for j := 0; j < len(pcr[0]); j++ {
				if pcr[0][j] != 0 {
					return false, nil
				}
			}
		}
		return true, nil
	} else {
		return false, fmt.Errorf("Not connected to TPM")
	}
}
