package test

import (
	"bytes"
	"crypto"
	"encoding/binary"

	"fmt"
	"strings"

	tss "github.com/9elements/go-tss"
	"github.com/9elements/txt-suite/pkg/api"
	tpm1 "github.com/google/go-tpm/tpm"
	tpm2 "github.com/google/go-tpm/tpm2"
)

const (
	tpm12PSIndex     = uint32(0x50000001)
	tpm12PSIndexSize = uint32(54)
	tpm12PSIndexAttr = tpm1.NVPerWriteSTClear // No attributes are set for TPM12 PS Index

	tpm12AUXIndex     = 0x50000003
	tpm12AUXIndexSize = uint32(64)
	tpm12AUXIndexAttr = uint32(0) // No attributes are set for TPM12 AUX Index

	tpm12OldAUXIndex = 0x50000002

	tpm12POIndex     = 0x40000001
	tpm12POIndexSize = uint32(54)
	tpm12POIndexAttr = tpm1.NVPerOwnerWrite

	tpm20PSIndex         = 0x1C10103
	tpm20PSIndexBaseSize = uint16(38)
	tpm20PSIndexAttr     = tpm2.AttrPolicyWrite + tpm2.AttrPolicyDelete +
		tpm2.AttrAuthRead + tpm2.AttrNoDA + tpm2.AttrPlatformCreate + tpm2.AttrWritten

	tpm20OldPSIndex = 0x1800001

	tpm20AUXIndex         = 0x1C10102
	tpm20AUXIndexBaseSize = uint16(40)
	tpm20AUXIndexAttr     = tpm2.AttrPolicyWrite + tpm2.AttrPolicyDelete +
		tpm2.AttrWriteSTClear + tpm2.AttrAuthRead + tpm2.AttrNoDA + tpm2.AttrPlatformCreate

	tpm20OldAUXIndex = 0x1800003

	tpm20POIndex         = 0x1C10106
	tpm20POIndexBaseSize = uint16(38)
	tpm20POIndexAttr     = tpm2.AttrOwnerWrite + tpm2.AttrPolicyWrite + tpm2.AttrAuthRead + tpm2.AttrNoDA

	tpm20OldPOIndex = 0x1400001

	tpm2LockedResult   = "error code 0x22"
	tpm2NVPublicNotSet = "error code 0xb"
	tpm12NVIndexNotSet = "the index to a PCR, DIR or other register is incorrect"
	tpm20NVIndexNotSet = "an NV Index is used before being initialized or the state saved by TPM2_Shutdown(STATE) could not be restored"
)

var (
	tpmCon *tss.TPM

	testtpmconnection = Test{
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
	testpsindexconfig = Test{
		Name:         "PS Index has correct config",
		function:     PSIndexConfig,
		Required:     true,
		dependencies: []*Test{&testtpmispresent},
		Status:       Implemented,
	}
	testauxindexconfig = Test{
		Name:         "AUX Index has correct config",
		function:     AUXIndexConfig,
		Required:     true,
		dependencies: []*Test{&testtpmispresent},
		Status:       Implemented,
	}
	testpoindexconfig = Test{
		Name:         "PO Index has correct config",
		function:     POIndexConfig,
		Required:     false,
		NonCritical:  true,
		dependencies: []*Test{&testtpmispresent},
		Status:       Implemented,
	}
	testpsindexissvalid = Test{
		Name:         "PS index has valid LCP Policy",
		function:     PSIndexHasValidLCP,
		Required:     true,
		dependencies: []*Test{&testtpmispresent},
		Status:       Implemented,
	}
	testpoindexissvalid = Test{
		Name:         "PO index has valid LCP Policy",
		function:     POIndexHasValidLCP,
		Required:     true,
		NonCritical:  true,
		dependencies: []*Test{&testtpmispresent},
		Status:       Implemented,
	}
	testpcr00valid = Test{
		Name:         "PCR 0 is set correctly",
		function:     PCR0IsSet,
		Required:     true,
		dependencies: []*Test{&testtpmispresent},
		Status:       Implemented,
	}

	// TestsTPM exposes the slice of pointers to tests regarding tpm functionality for txt
	TestsTPM = [...]*Test{
		&testtpmconnection,
		&testtpm12present,
		&testtpm2present,
		&testtpmispresent,
		&testtpmnvramislocked,
		&testpsindexconfig,
		&testauxindexconfig,
		&testpoindexconfig,
		&testpsindexissvalid,
		&testpoindexissvalid,
		&testpcr00valid,
	}
)

// TPMConnect Connects to a TPM device (virtual or real) at the given path
func TPMConnect(txtAPI api.ApiInterfaces) (bool, error, error) {

	t, err := tss.NewTPM()
	if err != nil {
		return false, nil, err
	}
	tpmCon = t
	return true, nil, nil
}

// TPM12Present Checks if TPM 1.2 is present and answers to GetCapability
func TPM12Present(txtAPI api.ApiInterfaces) (bool, error, error) {

	switch tpmCon.Version {
	case tss.TPMVersion12:
		return true, nil, nil
	case tss.TPMVersion20:
		return false, nil, nil
	}
	return false, nil, fmt.Errorf("unknown TPM version: %v ", tpmCon.Version)
}

// TPM2Present Checks if TPM 2.0 is present and answers to GetCapability
func TPM2Present(txtAPI api.ApiInterfaces) (bool, error, error) {
	switch tpmCon.Version {
	case tss.TPMVersion12:
		return false, nil, nil
	case tss.TPMVersion20:
		return true, nil, nil
	}
	return false, nil, fmt.Errorf("unknown TPM version: %v ", tpmCon.Version)
}

// TPMIsPresent validates if one of the two previous tests succeeded
func TPMIsPresent(txtAPI api.ApiInterfaces) (bool, error, error) {
	if (testtpm12present.Result == ResultPass) || (testtpm2present.Result == ResultPass) {
		return true, nil, nil
	}
	return false, fmt.Errorf("No TPM present"), nil
}

// TPMNVRAMIsLocked Checks if NVRAM indexes are write protected
func TPMNVRAMIsLocked(txtAPI api.ApiInterfaces) (bool, error, error) {
	var res bool
	var err error
	var flags tpm1.PermanentFlags
	switch tpmCon.Version {
	case tss.TPMVersion12:
		flags, err = tpm1.GetPermanentFlags(tpmCon.RWC)
		res = flags.NVLocked
	case tss.TPMVersion20:
		err = tpm2.HierarchyChangeAuth(tpmCon.RWC, tpm2.HandlePlatform, tpm2.AuthCommand{Session: tpm2.HandlePasswordSession, Attributes: tpm2.AttrContinueSession}, string(tpm2.EmptyAuth))
		res = strings.Contains(err.Error(), tpm2LockedResult)
	default:
		return false, nil, fmt.Errorf("unknown TPM version: %v ", tpmCon.Version)
	}
	if res != true {
		return false, nil, fmt.Errorf("%v  - - %v ", err, strings.Contains(err.Error(), tpm2LockedResult))
	}
	return res, nil, nil
}

// PSIndexConfig tests if PS Index has correct configuration
func PSIndexConfig(txtAPI api.ApiInterfaces) (bool, error, error) {
	var d1 tpm1.NVDataPublic
	var d2 tpm2.NVPublic
	var err error
	var raw []byte
	var p1 [3]byte
	var p2 [3]byte
	switch tpmCon.Version {
	case tss.TPMVersion12:
		raw, err = tpmCon.ReadNVPublic(tpm12PSIndex)
		if err != nil {
			return false, nil, err
		}
		buf := bytes.NewReader(raw)
		err = binary.Read(buf, binary.BigEndian, &d1)
		if err != nil {
			return false, nil, err
		}

		p1 = d1.PCRInfoRead.PCRsAtRelease.Mask
		p2 = d1.PCRInfoWrite.PCRsAtRelease.Mask
		if p1 != [3]byte{0, 0, 0} || p2 != [3]byte{0, 0, 0} {
			return false, fmt.Errorf("PCRInfos incorrect - Have PCRInfoRead: %v and PCRInfoWrite: %v - Want: PCRInfoRead [0,0,0] and PCRInfoWrite: [0,0,0]",
				d1.PCRInfoRead.PCRsAtRelease.Mask, d1.PCRInfoWrite.PCRsAtRelease.Mask), nil
		}

		// Intel Trusted Execution Technology Software Development Guide - Measured Launched Environment Developer’s Guide
		// August 2016 - Revision 013 - Document: 315168-013
		// Appendix J on page. 152, Table J-1. TPM Family 1.2 NV Storage Matrix
		if d1.Size != tpm12PSIndexSize {
			return false, fmt.Errorf("Size incorrect: Have: %v - Want: 54 - Data: %v", d1.Size, d1), nil
		}
		if d1.Permission.Attributes != tpm12PSIndexAttr {
			return false, fmt.Errorf("Permissions of PS Index are invalid - have: %v - want: %v", d1.Permission.Attributes, tpm12PSIndexAttr), nil
		}
		if d1.ReadSTClear != false {
			return false, fmt.Errorf("ReadSTClear is set - that is an error"), nil
		}
		if d1.WriteSTClear != false {
			return false, fmt.Errorf("WristeSTClear is set - that is an error"), nil
		}
		if d1.WriteDefine != true {
			return true, fmt.Errorf("WriteDefine is not set - This is no error for provisioning"), nil
		}
		return true, nil, nil
	case tss.TPMVersion20:
		raw, err = tpmCon.ReadNVPublic(tpm20OldPSIndex)
		if err != nil {
			if !strings.Contains(err.Error(), tpm2NVPublicNotSet) {
				return false, nil, err
			}
		}
		raw, err = tpmCon.ReadNVPublic(tpm20PSIndex)
		if err != nil {
			if strings.Contains(err.Error(), tpm2NVPublicNotSet) {
				return false, fmt.Errorf("PS indices not set"), err
			}
			return false, nil, err
		}
		buf := bytes.NewReader(raw)
		err = binary.Read(buf, binary.BigEndian, &d2.NVIndex)
		if err != nil {
			return false, nil, err
		}
		err = binary.Read(buf, binary.BigEndian, &d2.NameAlg)
		if err != nil {
			return false, nil, err
		}
		err = binary.Read(buf, binary.BigEndian, &d2.Attributes)
		if err != nil {
			return false, nil, err
		}
		// Helper variable hashSize- go-tpm2 does not implement proper structure
		var hashSize uint16
		err = binary.Read(buf, binary.BigEndian, &hashSize)
		if err != nil {
			return false, nil, err
		}
		// Uses hashSize to make the right sized slice to read the hash
		hashData := make([]byte, hashSize)
		err = binary.Read(buf, binary.BigEndian, &hashData)
		if err != nil {
			return false, nil, err
		}
		err = binary.Read(buf, binary.BigEndian, &d2.DataSize)
		if err != nil {
			return false, nil, err
		}

		// Intel Trusted Execution Technology Software Development Guide - Measured Launched Environment Developer’s Guide
		// August 2016 - Revision 013 - Document: 315168-013
		// Appendix J on page. 153, Table J-2. TPM Family 2.0 NV Storage Matrix
		if !checkTPM2NVAttr(d2.Attributes, tpm20PSIndexAttr, tpm2.AttrWritten) {
			return false, fmt.Errorf("TPM2 PS Index Attributes not correct. Have %v - Want: %v", d2.Attributes.String(), tpm20PSIndexAttr.String()), nil
		}

		size := (uint16(crypto.Hash(d2.NameAlg).Size())) + tpm20PSIndexBaseSize
		if d2.DataSize != size {
			return false, fmt.Errorf("TPM2 PS Index size incorrect. Have: %v - Want: %v", d2.DataSize, size), nil
		}
		return true, nil, nil
	}
	return false, fmt.Errorf("Not connected to TPM"), nil

}

// AUXIndexConfig tests if the AUX Index has the correct configuration
func AUXIndexConfig(txtAPI api.ApiInterfaces) (bool, error, error) {
	var d1 tpm1.NVDataPublic
	var d2 tpm2.NVPublic
	var err error
	var raw []byte
	var p1 [3]byte
	var p2 [3]byte
	switch tpmCon.Version {
	case tss.TPMVersion12:
		raw, err = tpmCon.ReadNVPublic(tpm12AUXIndex)
		if err != nil {
			return false, nil, err
		}
		buf := bytes.NewReader(raw)
		err = binary.Read(buf, binary.BigEndian, &d1)
		if err != nil {
			return false, nil, err
		}

		// Intel Trusted Execution Technology Software Development Guide - Measured Launched Environment Developer’s Guide
		// August 2016 - Revision 013 - Document: 315168-013
		// Appendix J on page. 152, Table J-1. TPM Family 1.2 NV Storage Matrix
		p1 = d1.PCRInfoRead.PCRsAtRelease.Mask
		p2 = d1.PCRInfoWrite.PCRsAtRelease.Mask
		if p1 != [3]byte{0, 0, 0} || p2 != [3]byte{0, 0, 0} {
			return false, fmt.Errorf("PCRInfos incorrect - Have PCRInfoRead: %v and PCRInfoWrite: %v - Want: PCRInfoRead 0 and PCRInfoWrite: 0",
				d1.PCRInfoRead.PCRsAtRelease.Mask, d1.PCRInfoWrite.PCRsAtRelease.Mask), nil
		}
		if d1.Permission.Attributes != 0 {
			return false, fmt.Errorf("Permissions of AUX Index are invalid - have: %v - want: %v", d1.Permission.Attributes, tpm12AUXIndexAttr), nil
		}
		if d1.Size != tpm12AUXIndexSize {
			return false, fmt.Errorf("Size incorrect: Have: %v - Want: 64", d1.Size), nil
		}
		if d1.ReadSTClear != false {
			return false, fmt.Errorf("ReadSTClear is set - that is an error"), nil
		}
		if d1.WriteSTClear != false {
			return false, fmt.Errorf("WristeSTClear is set - that is an error"), nil
		}
		if d1.WriteDefine != false {
			return true, fmt.Errorf("WriteDefine is set - This index is broken beyond repair"), nil
		}

		return true, nil, nil
	case tss.TPMVersion20:
		raw, err = tpmCon.ReadNVPublic(tpm20OldAUXIndex)
		if err != nil {
			if !strings.Contains(err.Error(), tpm20NVIndexNotSet) {
				return false, nil, err
			}
		}
		raw, err = tpmCon.ReadNVPublic(tpm20AUXIndex)
		if err != nil {
			if strings.Contains(err.Error(), tpm20NVIndexNotSet) {
				return false, fmt.Errorf("PS indices not set"), err
			}
			return false, nil, err
		}
		buf := bytes.NewReader(raw)
		err = binary.Read(buf, binary.BigEndian, &d2.NVIndex)
		if err != nil {
			return false, nil, err
		}
		err = binary.Read(buf, binary.BigEndian, &d2.NameAlg)
		if err != nil {
			return false, nil, err
		}
		err = binary.Read(buf, binary.BigEndian, &d2.Attributes)
		if err != nil {
			return false, nil, err
		}
		// Helper valiable hashSize- go-tpm2 does not implement proper structure
		var hashSize uint16
		err = binary.Read(buf, binary.BigEndian, &hashSize)
		if err != nil {
			return false, nil, err
		}
		// Uses hashSize to make the right sized slice to read the hash
		hashData := make([]byte, hashSize)
		err = binary.Read(buf, binary.BigEndian, &hashData)
		if err != nil {
			return false, nil, err
		}
		err = binary.Read(buf, binary.BigEndian, &d2.DataSize)
		if err != nil {
			return false, nil, err
		}

		// Intel Trusted Execution Technology Software Development Guide - Measured Launched Environment Developer’s Guide
		// August 2016 - Revision 013 - Document: 315168-013
		// Appendix J on page. 153, Table J-2. TPM Family 2.0 NV Storage Matrix
		if !checkTPM2NVAttr(d2.Attributes, tpm20AUXIndexAttr, tpm2.AttrWritten) {
			return false, fmt.Errorf("TPM2 AUX Index Attributes not correct. Have %v - Want: %v", d2.Attributes.String(), tpm20AUXIndexAttr.String()), nil
		}

		size := (uint16(crypto.Hash(d2.NameAlg).Size()) * 2) + tpm20AUXIndexBaseSize
		if d2.DataSize != size {
			return false, fmt.Errorf("TPM2 AUX Index size incorrect. Have: %v - Want: %v", d2.DataSize, size), nil
		}

		return true, nil, nil
	}
	return false, fmt.Errorf("not supported TPM device"), nil
}

// POIndexConfig checks the PO index configuration
func POIndexConfig(txtAPI api.ApiInterfaces) (bool, error, error) {
	var d1 tpm1.NVDataPublic
	var d2 tpm2.NVPublic
	var err error
	var raw []byte
	switch tpmCon.Version {
	case tss.TPMVersion12:
		raw, err = tpmCon.ReadNVPublic(tpm12POIndex)
		if err != nil {
			if strings.Contains(err.Error(), tpm12NVIndexNotSet) {
				return true, err, nil
			}
			return false, nil, err
		}
		buf := bytes.NewReader(raw)
		err = binary.Read(buf, binary.BigEndian, &d1)
		if err != nil {
			return false, nil, err
		}

		// Intel Trusted Execution Technology Software Development Guide - Measured Launched Environment Developer’s Guide
		// August 2016 - Revision 013 - Document: 315168-013
		// Appendix J on page. 152, Table J-1. TPM Family 1.2 NV Storage Matrix
		if d1.Permission.Attributes != 0 {
			return false, fmt.Errorf("Permissions of AUX Index are invalid - have: %v - want: %v", d1.Permission.Attributes, tpm12POIndexAttr), nil
		}
		if d1.Size != tpm12POIndexSize {
			return false, fmt.Errorf("TPM1 PO Index size incorrect. Have: %v - Want: %v", d1.Size, tpm12POIndexSize), nil
		}
	case tss.TPMVersion20:
		raw, err = tpmCon.ReadNVPublic(tpm20OldPOIndex)
		if err != nil {
			if !strings.Contains(err.Error(), tpm2NVPublicNotSet) {
				return false, nil, err
			}
		}
		//reset error
		err = nil
		raw, err = tpmCon.ReadNVPublic(tpm20POIndex)
		if err != nil {
			if strings.Contains(err.Error(), tpm2NVPublicNotSet) {
				return true, fmt.Errorf("PO index not set"), nil
			}
			return false, nil, err
		}
		buf := bytes.NewReader(raw)
		err = binary.Read(buf, binary.BigEndian, &d2.NVIndex)
		if err != nil {
			return false, nil, err
		}
		err = binary.Read(buf, binary.BigEndian, &d2.NameAlg)
		if err != nil {
			return false, nil, err
		}
		err = binary.Read(buf, binary.BigEndian, &d2.Attributes)
		if err != nil {
			return false, nil, err
		}
		// Helper valiable hashSize- go-tpm2 does not implement proper structure
		var hashSize uint16
		err = binary.Read(buf, binary.BigEndian, &hashSize)
		if err != nil {
			return false, nil, err
		}
		// Uses hashSize to make the right sized slice to read the hash
		hashData := make([]byte, hashSize)
		err = binary.Read(buf, binary.BigEndian, &hashData)
		if err != nil {
			return false, nil, err
		}
		err = binary.Read(buf, binary.BigEndian, &d2.DataSize)
		if err != nil {
			return false, nil, err
		}

		// Intel Trusted Execution Technology Software Development Guide - Measured Launched Environment Developer’s Guide
		// August 2016 - Revision 013 - Document: 315168-013
		// Appendix J on page. 153, Table J-2. TPM Family 2.0 NV Storage Matrix
		if !checkTPM2NVAttr(d2.Attributes, tpm20POIndexAttr, tpm2.AttrWritten) {
			return false, fmt.Errorf("TPM2 PO Index Attributes not correct. Have %v - Want: %v", d2.Attributes.String(), tpm20POIndexAttr.String()), nil
		}
		size := uint16(crypto.Hash(d2.NameAlg).Size()) + tpm20POIndexBaseSize

		if d2.DataSize != size {
			return false, fmt.Errorf("TPM2 PO Index incorrect. Have: %v - Want: %v", d2.DataSize, size), nil
		}
	}
	return false, nil, nil
}

// PSIndexHasValidLCP checks if PS Index has a valid LCP
func PSIndexHasValidLCP(txtAPI api.ApiInterfaces) (bool, error, error) {
	var pol1 *api.LCPPolicy
	var pol2 *api.LCPPolicy2
	emptyHash := make([]byte, 20)
	switch tpmCon.Version {
	case tss.TPMVersion12:
		data, err := tpmCon.NVReadValue(tpm12PSIndex, "", tpm12PSIndexSize, 0)
		if err != nil {
			return false, nil, err
		}
		pol1, pol2, err = api.ParsePolicy(data)
		if err != nil {
			return false, nil, err
		}
	case tss.TPMVersion20:
		var d tpm2.NVPublic
		var raw []byte
		var err error
		raw, err = tpmCon.ReadNVPublic(tpm20PSIndex)
		if err != nil {
			return false, nil, err
		}
		buf := bytes.NewReader(raw)
		err = binary.Read(buf, binary.BigEndian, &d.NVIndex)
		if err != nil {
			return false, nil, err
		}
		err = binary.Read(buf, binary.BigEndian, &d.NameAlg)
		if err != nil {
			return false, nil, err
		}
		err = binary.Read(buf, binary.BigEndian, &d.Attributes)
		if err != nil {
			return false, nil, err
		}
		// Helper valiable hashSize- go-tpm2 does not implement proper structure
		var hashSize uint16
		err = binary.Read(buf, binary.BigEndian, &hashSize)
		if err != nil {
			return false, nil, err
		}
		// Uses hashSize to make the right sized slice to read the hash
		hashData := make([]byte, hashSize)
		err = binary.Read(buf, binary.BigEndian, &hashData)
		if err != nil {
			return false, nil, err
		}
		err = binary.Read(buf, binary.BigEndian, &d.DataSize)
		if err != nil {
			return false, nil, err
		}

		data, err := tpmCon.NVReadValue(tpm20PSIndex, "", uint32(d.DataSize), tpm20PSIndex)
		if err != nil {
			if strings.Contains(err.Error(), tpm20NVIndexNotSet) {
				return true, fmt.Errorf("PS index not set"), nil
			}
			return false, nil, fmt.Errorf("error: %v, pubdata: %v", err, d)
		}
		pol1, pol2, err = api.ParsePolicy(data)
		if err != nil {
			return false, nil, err
		}
	}
	if pol1 != nil {
		if pol1.Version >= api.LCPPolicyVersion2 {
			return false, fmt.Errorf("invalid policy version. Have %v - Want: smaller %v", pol1.Version, api.LCPPolicyVersion2), nil
		}
		if pol1.HashAlg != 0 {
			return false, fmt.Errorf("HashAlg is invalid. Must be equal 0"), nil
		}
		if pol1.PolicyType != api.LCPPolicyTypeAny && pol1.PolicyType != api.LCPPolicyTypeList {
			return false, fmt.Errorf("PolicyType is invalid. Have: %v - Want: %v or %v", pol1.PolicyType, api.LCPPolicyTypeAny, api.LCPPolicyTypeList), nil
		}
		if pol1.SINITMinVersion == 0 {
			return false, fmt.Errorf("SINITMinVersion is invalid. Must be greater than 0"), nil
		}
		if pol1.PolicyType == api.LCPPolicyTypeList && pol1.PolicyControl == 0 {
			return false, fmt.Errorf("PolicyControl is invalid"), nil
		}
		if pol1.MaxSINITMinVersion != 0 {
			return false, fmt.Errorf("MaxSINITMinVersion is invalid. Must be greater than 0"), nil
		}
		if bytes.Equal(pol1.PolicyHash[:], emptyHash) {
			return false, fmt.Errorf("PolicyHash is invalid. Must be greater than 0"), nil
		}
		return true, nil, nil
	}
	if pol2 != nil {
		if pol2.Version < api.LCPPolicyVersion3 {
			return false, fmt.Errorf("wrong policy version. Have %v - Want: %v", pol2.Version, api.LCPPolicyVersion3), nil
		}
		switch pol2.HashAlg {
		case api.LCPPol2HAlgSHA1:
		case api.LCPPol2HAlgSHA256:
		case api.LCPPol2HAlgSHA384:
		case api.LCPPol2HAlgNULL:
		case api.LCPPol2HAlgSM3:
		default:
			return false, fmt.Errorf("HashAlg has invalid value"), nil
		}
		if pol2.PolicyType != api.LCPPolicyTypeAny && pol1.PolicyType != api.LCPPolicyTypeList {
			return false, fmt.Errorf("PolicyType is invalid. Have: %v - Want: %v or %v", pol1.PolicyType, api.LCPPolicyTypeAny, api.LCPPolicyTypeList), nil
		}
		if pol2.PolicyControl == 0 {
			return false, fmt.Errorf("PolicyControl is invalid. Must be greater than 0"), nil
		}
		if pol2.LcpHashAlgMask == 0 {
			return false, fmt.Errorf("LcpHashAlgMask is invalid. Must be greater than 0"), nil
		}
		if pol2.LcpSignAlgMask == 0 {
			return false, fmt.Errorf("LcpSignAlgMask is invalid. Must be greater than 0"), nil
		}
		return true, nil, nil
	}
	return false, fmt.Errorf("parse policy returned nil,nil, nil"), nil
}

// POIndexHasValidLCP checks if PO Index holds a valid LCP
func POIndexHasValidLCP(txtAPI api.ApiInterfaces) (bool, error, error) {
	var pol1 *api.LCPPolicy
	var pol2 *api.LCPPolicy2
	emptyHash := make([]byte, 20)

	switch tpmCon.Version {
	case tss.TPMVersion12:
		data, err := tpmCon.NVReadValue(tpm12POIndex, "", tpm12POIndexSize, 0)
		if err != nil {
			if strings.Contains(err.Error(), tpm12NVIndexNotSet) {
				return true, err, nil
			}
			return false, nil, err
		}
		pol1, pol2, err = api.ParsePolicy(data)
		if err != nil {
			return false, nil, err
		}
	case tss.TPMVersion20:
		var d tpm2.NVPublic
		var raw []byte
		var err error
		raw, err = tpmCon.ReadNVPublic(tpm20OldPOIndex)
		if err != nil {
			if !strings.Contains(err.Error(), tpm2NVPublicNotSet) {
				return false, nil, err
			}
		}
		//reset error
		err = nil
		raw, err = tpmCon.ReadNVPublic(tpm20POIndex)
		if err != nil {
			if strings.Contains(err.Error(), tpm2NVPublicNotSet) {
				return true, fmt.Errorf("PO index not set"), nil
			}
			return false, nil, err
		}
		buf := bytes.NewReader(raw)
		err = binary.Read(buf, binary.BigEndian, &d.NVIndex)
		if err != nil {
			return false, nil, err
		}
		err = binary.Read(buf, binary.BigEndian, &d.NameAlg)
		if err != nil {
			return false, nil, err
		}
		err = binary.Read(buf, binary.BigEndian, &d.Attributes)
		if err != nil {
			return false, nil, err
		}
		// Helper valiable hashSize- go-tpm2 does not implement proper structure
		var hashSize uint16
		err = binary.Read(buf, binary.BigEndian, &hashSize)
		if err != nil {
			return false, nil, err
		}
		// Uses hashSize to make the right sized slice to read the hash
		hashData := make([]byte, hashSize)
		err = binary.Read(buf, binary.BigEndian, &hashData)
		if err != nil {
			return false, nil, err
		}
		err = binary.Read(buf, binary.BigEndian, &d.DataSize)
		if err != nil {
			return false, nil, err
		}
		size := uint16(crypto.Hash(d.NameAlg).Size()) + tpm20POIndexBaseSize

		data, err := tpmCon.NVReadValue(tpm20POIndex, "", uint32(size), tpm20POIndex)
		pol1, pol2, err = api.ParsePolicy(data)
		if err != nil {
			return false, nil, err
		}
	}
	if pol1 != nil {
		if pol1.Version >= api.LCPPolicyVersion2 {
			return false, fmt.Errorf("invalid policy version. Have %v - Want: smaller %v", pol1.Version, api.LCPPolicyVersion2), nil
		}
		if pol1.HashAlg != 0 {
			return false, fmt.Errorf("HashAlg is invalid. Must be equal 0"), nil
		}
		if pol1.PolicyType != api.LCPPolicyTypeAny && pol1.PolicyType != api.LCPPolicyTypeList {
			return false, fmt.Errorf("PolicyType is invalid. Have: %v - Want: %v or %v", pol1.PolicyType, api.LCPPolicyTypeAny, api.LCPPolicyTypeList), nil
		}
		if pol1.SINITMinVersion == 0 {
			return false, fmt.Errorf("SINITMinVersion is invalid. Must be greater than 0"), nil
		}
		if pol1.PolicyType == api.LCPPolicyTypeList && pol1.PolicyControl == 0 {
			return false, fmt.Errorf("PolicyControl is invalid"), nil
		}
		if pol1.MaxSINITMinVersion != 0 {
			return false, fmt.Errorf("MaxSINITMinVersion is invalid. Must be greater than 0"), nil
		}
		if bytes.Equal(pol1.PolicyHash[:], emptyHash) {
			return false, fmt.Errorf("PolicyHash is invalid. Must be greater than 0"), nil
		}
		return true, nil, nil
	}
	if pol2 != nil {
		if pol2.Version < api.LCPPolicyVersion3 {
			return false, fmt.Errorf("wrong lcp policy version. Have %v - Want: %v", pol2.Version, api.LCPPolicyVersion3), nil
		}
		switch pol2.HashAlg {
		case api.LCPPol2HAlgSHA1:
		case api.LCPPol2HAlgSHA256:
		case api.LCPPol2HAlgSHA384:
		case api.LCPPol2HAlgNULL:
		case api.LCPPol2HAlgSM3:
		default:
			return false, fmt.Errorf("HashAlg has invalid value"), nil
		}
		if pol2.PolicyType != api.LCPPolicyTypeAny && pol1.PolicyType != api.LCPPolicyTypeList {
			return false, fmt.Errorf("PolicyType is invalid. Have: %v - Want: %v or %v", pol1.PolicyType, api.LCPPolicyTypeAny, api.LCPPolicyTypeList), nil
		}
		if pol2.PolicyControl == 0 {
			return false, fmt.Errorf("PolicyControl is invalid. Must be greater than 0"), nil
		}
		if pol2.LcpHashAlgMask == 0 {
			return false, fmt.Errorf("LcpHashAlgMask is invalid. Must be greater than 0"), nil
		}
		if pol2.LcpSignAlgMask == 0 {
			return false, fmt.Errorf("LcpSignAlgMask is invalid. Must be greater than 0"), nil
		}
		return true, nil, nil
	}
	return false, fmt.Errorf("parse policy returned nil,nil, nil"), nil
}

// PCR0IsSet Reads PCR-00 and checks whether if it's not the EmptyDigest
func PCR0IsSet(txtAPI api.ApiInterfaces) (bool, error, error) {
	pcr, err := tpmCon.ReadPCR(0)
	if err != nil {
		return false, nil, err
	}
	if bytes.Equal(pcr, []byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}) {
		return false, fmt.Errorf("PCR 0 is filled with zeros"), nil
	}
	return true, nil, nil
}

func checkTPM2NVAttr(mask, want, optional tpm2.NVAttr) bool {
	return (1 >> mask & (want | optional)) == 0
}
