package test

import (
	"bytes"
	"fmt"
	"io"
	"strings"

	tpm1 "github.com/google/go-tpm/tpm"
	"github.com/google/go-tpm/tpm2"

	"github.com/9elements/txt-suite/pkg/api"
)

const (
	tpm12PSIndex        = 0x50000001
	tpm12AUXIndex       = 0x50000003
	tpm12nvPerOwnerAuth = 0x00100000
	tpm12nvPerReadAuth  = 0x00200000
	tpm12OldAUXIndex    = 0x50000002
	tpm12POIndex        = 0x40000001
	tpm20PSIndex        = 0x1C10103
	tpm20OldPSIndex     = 0x1800001
	tpm20AUXIndex       = 0x1C10102
	tpm20OldAUXIndex    = 0x1800003
	tpm20POIndex        = 0x1C10106
	tpm20OldPOIndex     = 0x1400001

	tpm2LockedResult = "error code 0x22"
)

var (
	tpm12Connection *io.ReadWriteCloser = nil
	tpm20Connection *io.ReadWriteCloser = nil
	// TpmPath exposes the used path for tpm device
	TpmPath           string = "/dev/tpm0"
	testtpmconnection        = Test{
		Name:     "TPM connection",
		Required: true,
		function: TPMConnect,
		Status:   Implemented,
	}
	testtpm12present = Test{
		Name:         "TPM 1.2 present",
		Required:     false,
		NonCritical:  true,
		function:     TPM12Present,
		dependencies: []*Test{&testtpmconnection},
		Status:       Implemented,
	}
	testtpm2present = Test{
		Name:         "TPM 2 is present",
		Required:     false,
		NonCritical:  true,
		function:     TPM2Present,
		dependencies: []*Test{&testtpmconnection},
		Status:       Implemented,
	}
	testtpmispresent = Test{
		Name:         "TPM is present",
		Required:     true,
		function:     TPMIsPresent,
		dependencies: []*Test{&testtpmconnection},
		Status:       Implemented,
	}
	testtpmnvramislocked = Test{
		Name:         "TPM NVRAM is locked",
		function:     TPMNVRAMIsLocked,
		Required:     true,
		dependencies: []*Test{&testtpmispresent},
		Status:       Implemented,
	}
	testpsindexisset = Test{
		Name:         "PS index set in NVRAM",
		function:     PSIndexIsSet,
		Required:     true,
		dependencies: []*Test{&testtpmispresent},
		Status:       Implemented,
	}
	testauxindexisset = Test{
		Name:         "AUX index set in NVRAM",
		function:     AUXIndexIsSet,
		Required:     true,
		dependencies: []*Test{&testtpmispresent},
		Status:       Implemented,
	}
	testlcppolicyisvalid = Test{
		Name:         "PS index has valid LCP Policy",
		function:     LCPPolicyIsValid,
		Required:     true,
		dependencies: []*Test{&testtpmispresent, &testpsindexisset},
		Status:       Implemented,
	}

	// TestsTPM exposes the slice of pointers to tests regarding tpm functionality for txt
	TestsTPM = [...]*Test{
		&testtpmconnection,
		&testtpm12present,
		&testtpm2present,
		&testtpmispresent,
		&testtpmnvramislocked,
		&testpsindexisset,
		&testauxindexisset,
		&testlcppolicyisvalid,
	}
)

// TPMConnect Connects to a TPM device (virtual or real) at the given path
func TPMConnect() (bool, error, error) {
	conn, err := tpm2.OpenTPM(TpmPath)

	if err != nil {
		conn, err = tpm1.OpenTPM(TpmPath)

		if err != nil {
			return false, nil, fmt.Errorf("cannot connect to TPM: %s", err)
		}

		tpm12Connection = &conn
		return true, nil, nil
	}

	tpm20Connection = &conn
	return true, nil, nil
}

// TPM12Present Checks if TPM 1.2 is present and answers to GetCapability
func TPM12Present() (bool, error, error) {
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

// TPM2Present Checks if TPM 2.0 is present and answers to GetCapability
func TPM2Present() (bool, error, error) {
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

// TPMIsPresent validates if one of the two previous tests succeeded
func TPMIsPresent() (bool, error, error) {
	if (testtpm12present.Result == ResultPass) || (testtpm2present.Result == ResultPass) {
		return true, nil, nil
	}
	return false, fmt.Errorf("No TPM present"), nil
}

// TPMNVRAMIsLocked Checks if NVRAM indexes are write protected
func TPMNVRAMIsLocked() (bool, error, error) {
	if tpm12Connection != nil {
		flags, err := tpm1.GetPermanentFlags(*tpm12Connection)

		return flags.NVLocked, err, nil
	} else if tpm20Connection != nil {
		err := tpm2.HierarchyChangeAuth(*tpm20Connection, tpm2.HandlePlatform, tpm2.AuthCommand{Session: tpm2.HandlePasswordSession, Attributes: tpm2.AttrContinueSession}, string(tpm2.EmptyAuth))
		if err != nil && strings.Contains(err.Error(), tpm2LockedResult) {
			return true, nil, nil
		}
		return false, fmt.Errorf("Platform hierarchy not defined or auth is empty buffer"), nil
	} else {
		return false, nil, fmt.Errorf("No TPM connection")
	}
}

// PSIndexIsSet TPM NVRAM has a valid PS index
func PSIndexIsSet() (bool, error, error) {
	if tpm12Connection != nil {
		data, err := tpm1.NVReadValue(*tpm12Connection, tpm12PSIndex, 0, 54, nil)
		if err != nil {
			return false, nil, err
		}

		if len(data) != 54 {
			return false, fmt.Errorf("TestPSIndexIsSet: TPM1 - Length of data not 54 "), nil
		}
		return true, nil, nil
	} else if tpm20Connection != nil {
		meta, err := tpm2.NVReadPublic(*tpm20Connection, tpm20PSIndex)
		if err != nil {
			meta, err := tpm2.NVReadPublic(*tpm20Connection, tpm20OldPSIndex)
			if err != nil {
				return false, fmt.Errorf("TestPSIndexIsSet: TPM2 - No PS index found"), err
			}
			if meta.NVIndex != tpm20OldPSIndex {
				return false, fmt.Errorf("TestPSIndexIsSet: TPM2 - PS Index Addresses don't match"), nil
			}
		}
		if meta.NVIndex != tpm20PSIndex {
			return false, fmt.Errorf("TestPSIndexIsSet: TPM2 - PS Index Addresses don't match"), nil
		}
		return true, nil, nil
	} else {
		return false, fmt.Errorf("Not connected to TPM"), nil
	}
}

// AUXIndexIsSet has a valid AUX index
func AUXIndexIsSet() (bool, error, error) {
	if tpm12Connection != nil {
		buf, err := tpm1.NVReadValue(*tpm12Connection, tpm12AUXIndex, 0, 1, nil)
		if err != nil {
			return false, nil, err
		}
		if len(buf) != 1 {
			return false, fmt.Errorf("TPM AUX Index not set"), nil
		}

		return true, nil, nil
	} else if tpm20Connection != nil {
		meta, err := tpm2.NVReadPublic(*tpm20Connection, tpm20AUXIndex)
		if err != nil {
			return false, nil, err
		}
		if meta.NVIndex != tpm20AUXIndex {
			return false, fmt.Errorf("AUXIndexIsSet: AUXIndex Addresses don't match"), nil
		}
		return true, nil, nil
	} else {
		return false, nil, fmt.Errorf("Not connected to TPM")
	}
}

// LCPPolicyIsValid Validates LCPPolicy against PS index
func LCPPolicyIsValid() (bool, error, error) {
	var data []byte
	var err error

	if tpm12Connection != nil {
		data, err = tpm1.NVReadValue(*tpm12Connection, tpm12PSIndex, 0, 54, nil)

		if err != nil {
			return false, nil, err
		}
	} else if tpm20Connection != nil {
		data, err = tpm2.NVRead(*tpm20Connection, tpm20PSIndex)

		if err != nil {
			return false, nil, err
		}
	} else {
		return false, nil, fmt.Errorf("Not connected to TPM")
	}

	pol, pol2, err := api.ParsePolicy(data)
	if err != nil {
		return false, nil, err
	}

	if tpm12Connection != nil {
		if pol.Version > 0x204 || pol.Version < 0x200 {
			return false, fmt.Errorf("LCP-Version invalid"), nil
		}
	} else if tpm20Connection != nil {
		if pol2.Version > 0x302 || pol2.Version < 0x300 {
			return false, fmt.Errorf("LCP-Version invalid"), nil
		}
	} else {
		return false, fmt.Errorf("LCP-Version invalid"), nil
	}

	return true, nil, nil
}

// PCR0IsSet Reads PCR-00 and checks whether if it's not the EmptyDigest
func PCR0IsSet() (bool, error, error) {
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
