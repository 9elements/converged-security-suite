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
	tpm12Connection   *io.ReadWriteCloser = nil
	tpm20Connection   *io.ReadWriteCloser = nil
	TpmPath           string              = "/dev/tpm0"
	testtpmconnection                     = Test{
		Name:     "TPM connection",
		Required: true,
		function: TestTPMConnect,
		Status:   TestImplemented,
	}
	testtpm12present = Test{
		Name:         "TPM 1.2 present",
		Required:     false,
		function:     TestTPM12Present,
		dependencies: []*Test{&testtpmconnection},
		Status:       TestImplemented,
	}
	testtpm2present = Test{
		Name:         "TPM 2 is present",
		Required:     false,
		function:     TestTPM2Present,
		dependencies: []*Test{&testtpmconnection},
		Status:       TestImplemented,
	}
	testtpmispresent = Test{
		Name:         "TPM is present",
		Required:     true,
		function:     TestTPMIsPresent,
		dependencies: []*Test{&testtpmconnection},
		Status:       TestImplemented,
	}
	testtpmislocked = Test{
		Name:         "TPM in production mode",
		function:     TestTPMIsLocked,
		Required:     false,
		dependencies: []*Test{&testtpmispresent},
		Status:       TestPartlyImplemented,
	}
	testpsindexisset = Test{
		Name:         "PS index set in NVRAM",
		function:     TestPSIndexIsSet,
		Required:     true,
		dependencies: []*Test{&testtpmispresent},
		Status:       TestImplemented,
	}
	testauxindexisset = Test{
		Name:         "AUX index set in NVRAM",
		function:     TestAUXIndexIsSet,
		Required:     true,
		dependencies: []*Test{&testtpmispresent},
		Status:       TestImplemented,
	}
	testlcppolicyisvalid = Test{
		Name:         "PS index has valid LCP Policy",
		function:     TestLCPPolicyIsValid,
		Required:     true,
		dependencies: []*Test{&testtpmispresent, &testpsindexisset},
		Status:       TestImplemented,
	}

	TestsTPM = [...]*Test{
		&testtpmconnection,
		&testtpm12present,
		&testtpm2present,
		&testtpmispresent,
		&testtpmislocked,
		&testpsindexisset,
		&testauxindexisset,
		&testlcppolicyisvalid,
	}
)

// Connects to a TPM device (virtual or real) at the given path
func TestTPMConnect() (bool, error, error) {
	conn, err := tpm2.OpenTPM(TpmPath)

	if err != nil {
		conn, err = tpm1.OpenTPM(TpmPath)

		if err != nil {
			return false, nil, fmt.Errorf("Cannot connect to TPM: %s\n", err)
		}

		tpm12Connection = &conn
		return true, nil, nil
	}

	tpm20Connection = &conn
	return true, nil, nil
}

// Checks if TPM 1.2 is present and answers to GetCapability
func TestTPM12Present() (bool, error, error) {
	if tpm12Connection == nil {
		return false, fmt.Errorf("No TPM 1.2 connection"), nil
	}
	vid, err := tpm1.GetManufacturer(*tpm12Connection)
	if err != nil {
		return false, nil, err
	}
	if vid == nil {
		return false, fmt.Errorf("TestTPM12Present: GetManufacturer() didn't return anything"), nil
	}
	return true, nil, nil

}

func TestTPM2Present() (bool, error, error) {
	if tpm20Connection == nil {
		return false, fmt.Errorf("No TPM 2 connection"), nil
	}
	ca, _, err := tpm2.GetCapability(*tpm20Connection, tpm2.CapabilityTPMProperties, 1, uint32(tpm2.Manufacturer))
	if err != nil {
		return false, nil, err
	}
	if ca == nil {
		return false, fmt.Errorf("TestTPM2Present: no Manufacturer returned"), nil
	}
	return true, nil, nil
}

func TestTPMIsPresent() (bool, error, error) {
	if (testtpm12present.Result == ResultPass) || (testtpm2present.Result == ResultPass) {
		return true, nil, nil
	}
	return false, fmt.Errorf("No TPM present"), nil
}

// TPM NVRAM is locked
func TestTPMIsLocked() (bool, error, error) {
	if tpm12Connection != nil {
		flags, err := tpm1.GetPermanentFlags(*tpm12Connection)

		return flags.NvLocked, err, nil
	} else if tpm20Connection != nil {
		return false, nil, fmt.Errorf("Unimplemented: TPM 2.0")
	} else {
		return false, nil, fmt.Errorf("No TPM connection")
	}
}

// TPM NVRAM has a valid PS index
func TestPSIndexIsSet() (bool, error, error) {
	if tpm12Connection != nil {
		data, err := tpm1.NVReadValueNoAuth(*tpm12Connection, psIndex, 0, 54)
		if err != nil {
			return false, nil, err
		}

		if len(data) != 54 {
			return false, fmt.Errorf("TestPSIndexIsSet: TPM1 - Length of data not 54 "), nil
		}
		return true, nil, nil
	} else if tpm20Connection != nil {
		meta, err := tpm2.NVReadPublic(*tpm20Connection, psIndex)
		if err != nil {
			return false, nil, err
		}

		rc := true
		rc = rc && meta.NVIndex == psIndex
		if rc != true {
			return false, fmt.Errorf("TestPSIndexIsSet: TPM2 - PS Index Addresses don't match"), nil
		}
		rc = rc && (meta.Attributes&tpm2.KeyProp(tpm2.AttrWriteLocked) != 0)

		if rc != true {
			return false, fmt.Errorf("TestPSIndexIsSet: TPM2 - WriteLock not set"), nil
		}
		return true, nil, nil
	} else {
		return false, fmt.Errorf("Not connected to TPM"), nil
	}
}

// TPM NVRAM has a valid AUX index
func TestAUXIndexIsSet() (bool, error, error) {
	if tpm12Connection != nil {
		buf, err := tpm1.NVReadValueNoAuth(*tpm12Connection, auxIndex, 0, 1)

		return len(buf) == 1, err, nil
	} else if tpm20Connection != nil {
		meta, err := tpm2.NVReadPublic(*tpm20Connection, auxIndex)
		if err != nil {
			return false, nil, err
		}
		if meta.NVIndex != auxIndex {
			return false, fmt.Errorf("AUXIndexIsSet: AUXIndex Addresses don't match"), nil
		}
		return true, nil, nil
	} else {
		return false, nil, fmt.Errorf("Not connected to TPM")
	}
}

// PS index contains a valid LCP policy
func TestLCPPolicyIsValid() (bool, error, error) {
	var data []byte
	var err error

	if tpm12Connection != nil {
		data, err = tpm1.NVReadValueNoAuth(*tpm12Connection, psIndex, 0, 54)

		if err != nil {
			return false, nil, err
		}
	} else if tpm20Connection != nil {
		data, err = tpm2.NVRead(*tpm20Connection, psIndex)

		if err != nil {
			return false, nil, err
		}
	} else {
		return false, nil, fmt.Errorf("Not connected to TPM")
	}

	lcp, err := api.ParsePolicy(data)
	if err != nil {
		return false, nil, err
	}

	if lcp.Version >= 0x300 {
		return false, fmt.Errorf("LCP-Version invalid"), nil
	}
	return true, nil, nil
}

// Reads PCR-00 and checks whether if it's not the EmptyDigest
func TestPCR0IsSet() (bool, error, error) {
	if tpm12Connection != nil {
		pcr, err := tpm1.ReadPCR(*tpm12Connection, 0)
		if err != nil {
			return false, nil, err
		}
		if pcr == nil {
			return false, fmt.Errorf("No PCR returned"), nil
		}
		if bytes.Equal(pcr, []byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}) {
			return true, nil, nil
		}

		return false, fmt.Errorf("PCR not set correctly"), nil
	} else if tpm20Connection != nil {
		ca, _, err := tpm2.GetCapability(*tpm20Connection, tpm2.CapabilityPCRs, 1, 0)
		if err != nil {
			return false, nil, err
		}
		if ca == nil {
			return false, fmt.Errorf("GetCapability didn't return anything"), nil
		}

		for i := 0; i < 4; i++ {
			pcr, _ := tpm2.ReadPCRs(*tpm20Connection, ca[i].(tpm2.PCRSelection))
			for j := 0; j < len(pcr[0]); j++ {
				if pcr[0][j] != 0 {
					return false, nil, nil
				}
			}
		}
		return true, nil, nil
	} else {
		return false, fmt.Errorf("Not connected to TPM"), nil
	}
}
