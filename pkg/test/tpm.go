package test

import (
	"bytes"
	"crypto"
	"encoding/binary"
	"fmt"
	"strings"

	"github.com/9elements/converged-security-suite/v2/pkg/tools"
	"github.com/9elements/go-linux-lowlevel-hw/pkg/hwapi"
	tpm1 "github.com/google/go-tpm/tpm"
	"github.com/google/go-tpm/legacy/tpm2"
)

// nolint
const (
	// Intel Trusted Execution Technology Software Development Guide - Measured Launched Environment Developer’s Guide
	// August 2016 - Revision 013 - Document: 315168-013
	// Appendix J on page. 152, Table J-1. TPM Family 1.2 NV Storage Matrix
	tpm12PSIndex     = uint32(0x50000001)
	tpm12PSIndexSize = uint32(54)
	tpm12PSIndexAttr = tpm1.NVPerWriteSTClear // No attributes are set for TPM12 PS Index

	tpm12AUXIndex     = 0x50000003
	tpm12AUXIndexSize = uint32(64)
	tpm12AUXIndexAttr = uint32(0) // No attributes are set for TPM12 AUX Index

	tpm12OldAUXIndex = 0x50000002 // nolint

	tpm12POIndex     = 0x40000001
	tpm12POIndexSize = uint32(54)
	tpm12POIndexAttr = tpm1.NVPerOwnerWrite

	// Intel Trusted Execution Technology Software Development Guide - Measured Launched Environment Developer’s Guide
	// August 2016 - Revision 013 - Document: 315168-013
	// Appendix J on page. 152, Table J-1. TPM Family 2.0 NV Storage Matrix
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
	tpm20AUXIndexHashData = []byte{0xEF, 0x9A, 0x26, 0xFC, 0x22, 0xD1, 0xAE, 0x8C, 0xEC, 0xFF, 0x59, 0xE9, 0x48, 0x1A, 0xC1, 0xEC, 0x53, 0x3D, 0xBE, 0x22, 0x8B, 0xEC, 0x6D, 0x17, 0x93, 0x0F, 0x4C, 0xB2, 0xCC, 0x5B, 0x97, 0x24}

	testtpmconnection = Test{
		Name:     "TPM connection",
		Required: true,
		function: TPMConnect,
		Status:   Implemented,
	}
	testtpmispresent = Test{
		Name:         "TPM is present",
		Required:     true,
		function:     TPMIsPresent,
		dependencies: []*Test{&testtpmconnection},
		Status:       Implemented,
	}
	testtpmnvramislocked = Test{
		Name:                    "TPM NVRAM is locked",
		function:                TPMNVRAMIsLocked,
		Required:                true,
		dependencies:            []*Test{&testtpmispresent},
		Status:                  Implemented,
		SpecificationChapter:    "5.6.3.1 Failsafe Hash",
		SpecificiationTitle:     IntelTXTBGSBIOSSpecificationTitle,
		SpecificationDocumentID: IntelTXTBGSBIOSSpecificationDocumentID,
	}
	testpsindexconfig = Test{
		Name:                    "PS Index has correct config",
		function:                PSIndexConfig,
		Required:                true,
		dependencies:            []*Test{&testtpmispresent},
		Status:                  Implemented,
		SpecificationChapter:    "I TPM NV",
		SpecificiationTitle:     IntelTXTSpecificationTitle,
		SpecificationDocumentID: IntelTXTSpecificationDocumentID,
	}
	testauxindexconfig = Test{
		Name:                    "AUX Index has correct config",
		function:                AUXIndexConfig,
		Required:                true,
		dependencies:            []*Test{&testtpmispresent},
		Status:                  Implemented,
		SpecificationChapter:    "I TPM NV",
		SpecificiationTitle:     IntelTXTSpecificationTitle,
		SpecificationDocumentID: IntelTXTSpecificationDocumentID,
	}
	testauxindexhashdata = Test{
		Name:                    "AUX Index has the correct hash",
		function:                AUXTPM2IndexCheckHash,
		Required:                true,
		dependencies:            []*Test{&testtpmispresent},
		Status:                  Implemented,
		SpecificationChapter:    "I TPM NV",
		SpecificiationTitle:     IntelTXTSpecificationTitle,
		SpecificationDocumentID: IntelTXTSpecificationDocumentID,
	}
	testpoindexconfig = Test{
		Name:                    "PO Index has correct config",
		function:                POIndexConfig,
		Required:                false,
		dependencies:            []*Test{&testtpmispresent},
		Status:                  Implemented,
		SpecificationChapter:    "I TPM NV",
		SpecificiationTitle:     IntelTXTSpecificationTitle,
		SpecificationDocumentID: IntelTXTSpecificationDocumentID,
	}
	testpsindexissvalid = Test{
		Name:                    "PS index has valid LCP Policy",
		function:                PSIndexHasValidLCP,
		Required:                true,
		dependencies:            []*Test{&testtpmispresent},
		Status:                  Implemented,
		SpecificationChapter:    "D.3 LCP_POLICY_LIST",
		SpecificiationTitle:     IntelTXTSpecificationTitle,
		SpecificationDocumentID: IntelTXTSpecificationDocumentID,
	}
	testpoindexissvalid = Test{
		Name:                    "PO index has valid LCP Policy",
		function:                POIndexHasValidLCP,
		Required:                true,
		dependencies:            []*Test{&testtpmispresent},
		Status:                  Implemented,
		SpecificationChapter:    "D.3 LCP_POLICY_LIST",
		SpecificiationTitle:     IntelTXTSpecificationTitle,
		SpecificationDocumentID: IntelTXTSpecificationDocumentID,
	}
	testpcr00valid = Test{
		Name:                    "PCR 0 is set correctly",
		function:                PCR0IsSet,
		Required:                true,
		dependencies:            []*Test{&testtpmispresent},
		Status:                  Implemented,
		SpecificationChapter:    "BIOS Startup Module (Type 0x07) Entry",
		SpecificiationTitle:     IntelTXTBGSBIOSSpecificationTitle,
		SpecificationDocumentID: IntelTXTBGSBIOSSpecificationDocumentID,
	}
	testpsnpwmodenotactive = Test{
		Name:                    "NPW mode is deactivated in PS policy",
		function:                NPWModeIsNotSetInPS,
		Required:                true,
		dependencies:            []*Test{&testpsindexissvalid},
		Status:                  Implemented,
		SpecificationChapter:    "4.1.4 Supported Platform Configurations",
		SpecificiationTitle:     IntelTXTBGSBIOSSpecificationTitle,
		SpecificationDocumentID: IntelTXTBGSBIOSSpecificationDocumentID,
	}
	testtxtmodvalid = Test{
		Name:                    "TXT mode is valid",
		function:                TXTModeValid,
		Required:                true,
		dependencies:            []*Test{&testpsindexissvalid},
		Status:                  Implemented,
		SpecificationChapter:    "5.6.2 Autopromotion Hash and Signed BIOS Policy",
		SpecificiationTitle:     IntelTXTBGSBIOSSpecificationTitle,
		SpecificationDocumentID: IntelTXTBGSBIOSSpecificationDocumentID,
	}

	// TestsTPM exposes the slice of pointers to tests regarding tpm functionality for txt
	TestsTPM = [...]*Test{
		&testtpmconnection,
		&testtpmispresent,
		&testtpmnvramislocked,
		&testpsindexconfig,
		&testauxindexconfig,
		&testauxindexhashdata,
		&testpoindexconfig,
		&testpsindexissvalid,
		&testpoindexissvalid,
		&testpcr00valid,
		&testpsnpwmodenotactive,
		&testtxtmodvalid,
	}
)

// TPMConnect Connects to a TPM device (virtual or real)
func TPMConnect(txtAPI hwapi.LowLevelHardwareInterfaces, p *PreSet) (bool, error, error) {
	tpmCon, err := txtAPI.NewTPM()
	if err == nil && tpmCon != nil {
		defer tpmCon.Close()
		return true, nil, nil
	}
	return false, nil, err
}

// TPMIsPresent validates if one of the two previous tests succeeded
func TPMIsPresent(txtAPI hwapi.LowLevelHardwareInterfaces, p *PreSet) (bool, error, error) {
	tpmCon, err := txtAPI.NewTPM()
	if err != nil {
		return false, fmt.Errorf("no TPM connection"), nil
	}
	defer tpmCon.Close()
	if tpmCon.Version == p.TPM {
		return true, nil, nil
	}
	return false, fmt.Errorf("no TPM present"), nil
}

// TPMNVRAMIsLocked Checks if NVRAM indexes are write protected
func TPMNVRAMIsLocked(txtAPI hwapi.LowLevelHardwareInterfaces, p *PreSet) (bool, error, error) {
	tpmCon, err := txtAPI.NewTPM()
	if err != nil {
		return false, fmt.Errorf("no TPM connection"), nil
	}
	defer tpmCon.Close()
	res, err := txtAPI.NVLocked(tpmCon)
	return res, err, nil
}

// PSIndexConfig tests if PS Index has correct configuration
func PSIndexConfig(txtAPI hwapi.LowLevelHardwareInterfaces, p *PreSet) (bool, error, error) {
	var d1 tpm1.NVDataPublic
	var d2 tpm2.NVPublic
	var err error
	var raw []byte
	var p1 [3]byte
	var p2 [3]byte
	tpmCon, err := txtAPI.NewTPM()
	if err != nil {
		return false, fmt.Errorf("no TPM connection"), nil
	}
	defer tpmCon.Close()
	switch tpmCon.Version {
	case hwapi.TPMVersion12:
		raw, err = txtAPI.ReadNVPublic(tpmCon, tpm12PSIndex)
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
			return false, fmt.Errorf("size incorrect: Have: %v - Want: 54 - Data: %v", d1.Size, d1), nil
		}
		if d1.Permission.Attributes != tpm12PSIndexAttr {
			return false, fmt.Errorf("permissions of PS Index are invalid - have: %v - want: %v", d1.Permission.Attributes, tpm12PSIndexAttr), nil
		}
		if d1.ReadSTClear {
			return false, fmt.Errorf("ReadSTClear is set - that is an error"), nil
		}
		if d1.WriteSTClear {
			return false, fmt.Errorf("WristeSTClear is set - that is an error"), nil
		}
		if !d1.WriteDefine {
			return true, fmt.Errorf("WriteDefine is not set - This is no error for provisioning"), nil
		}
		return true, nil, nil
	case hwapi.TPMVersion20:
		raw, err = txtAPI.ReadNVPublic(tpmCon, tpm20PSIndex)
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
	return false, fmt.Errorf("not connected to TPM"), nil

}

// AUXIndexConfig tests if the AUX Index has the correct configuration
func AUXIndexConfig(txtAPI hwapi.LowLevelHardwareInterfaces, p *PreSet) (bool, error, error) {
	var d1 tpm1.NVDataPublic
	var d2 tpm2.NVPublic
	var err error
	var raw []byte
	var p1 [3]byte
	var p2 [3]byte
	tpmCon, err := txtAPI.NewTPM()
	if err != nil {
		return false, fmt.Errorf("no TPM connection"), nil
	}
	defer tpmCon.Close()
	switch tpmCon.Version {
	case hwapi.TPMVersion12:
		raw, err = txtAPI.ReadNVPublic(tpmCon, tpm12AUXIndex)
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
			return false, fmt.Errorf("permissions of AUX Index are invalid - have: %v - want: %v", d1.Permission.Attributes, tpm12AUXIndexAttr), nil
		}
		if d1.Size != tpm12AUXIndexSize {
			return false, fmt.Errorf("size incorrect: Have: %v - Want: 64", d1.Size), nil
		}
		if d1.ReadSTClear {
			return false, fmt.Errorf("ReadSTClear is set - that is an error"), nil
		}
		if d1.WriteSTClear {
			return false, fmt.Errorf("WristeSTClear is set - that is an error"), nil
		}
		if d1.WriteDefine {
			return true, fmt.Errorf("WriteDefine is set - This index is broken beyond repair"), nil
		}

		return true, nil, nil
	case hwapi.TPMVersion20:
		raw, err = txtAPI.ReadNVPublic(tpmCon, tpm20AUXIndex)
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

// AUXTPM2IndexCheckHash checks the PolicyHash of AUX index
func AUXTPM2IndexCheckHash(txtAPI hwapi.LowLevelHardwareInterfaces, p *PreSet) (bool, error, error) {
	tpmCon, err := txtAPI.NewTPM()
	if err != nil {
		return false, fmt.Errorf("no TPM connection"), nil
	}
	defer tpmCon.Close()
	switch tpmCon.Version {
	case hwapi.TPMVersion12:
		return false, fmt.Errorf("only valid for TPM 2.0"), nil
	case hwapi.TPMVersion20:
		var d tpm2.NVPublic
		raw, err := txtAPI.ReadNVPublic(tpmCon, tpm20AUXIndex)
		if err != nil {
			if strings.Contains(err.Error(), tpm20NVIndexNotSet) {
				return false, fmt.Errorf("PS indices not set"), err
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

		if bytes.Equal(hashData, tpm20AUXIndexHashData) {
			return true, nil, nil
		}
		return false, fmt.Errorf("AUX index has a incorrect PolicyHash. Have: %v - Want: %v", hashData, tpm20AUXIndexHashData), nil
	}
	return false, fmt.Errorf("unknown TPM device version"), nil
}

// POIndexConfig checks the PO index configuration
func POIndexConfig(txtAPI hwapi.LowLevelHardwareInterfaces, p *PreSet) (bool, error, error) {
	var d1 tpm1.NVDataPublic
	var d2 tpm2.NVPublic
	var err error
	var raw []byte
	tpmCon, err := txtAPI.NewTPM()
	if err != nil {
		return false, fmt.Errorf("no TPM connection"), nil
	}
	defer tpmCon.Close()
	switch tpmCon.Version {
	case hwapi.TPMVersion12:
		raw, err = txtAPI.ReadNVPublic(tpmCon, tpm12POIndex)
		if err != nil {
			if strings.Contains(err.Error(), tpm12NVIndexNotSet) {
				return true, fmt.Errorf("PO Index not set"), nil
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
			return false, fmt.Errorf("permissions of AUX Index are invalid - have: %v - want: %v", d1.Permission.Attributes, tpm12POIndexAttr), nil
		}
		if d1.Size != tpm12POIndexSize {
			return false, fmt.Errorf("TPM1 PO Index size incorrect. Have: %v - Want: %v", d1.Size, tpm12POIndexSize), nil
		}
	case hwapi.TPMVersion20:
		raw, err = txtAPI.ReadNVPublic(tpmCon, tpm20POIndex)
		if err != nil {
			if strings.Contains(err.Error(), tpm2NVPublicNotSet) {
				return false, fmt.Errorf("PO index not set"), nil
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
	return false, fmt.Errorf("unknown TPM device version"), nil
}

// PSIndexHasValidLCP checks if PS Index has a valid LCP
func PSIndexHasValidLCP(txtAPI hwapi.LowLevelHardwareInterfaces, p *PreSet) (bool, error, error) {
	emptyHash := make([]byte, 20)
	pol1, pol2, err := readPSLCPPolicy(txtAPI)
	if err != nil {
		return false, err, nil
	}
	if pol1 != nil {
		if pol1.Version >= tools.LCPPolicyVersion2 {
			return false, fmt.Errorf("invalid policy version. Have %v - Want: smaller %v", pol1.Version, tools.LCPPolicyVersion2), nil
		}
		if pol1.HashAlg != tools.LCPPolHAlgSHA1 {
			return false, fmt.Errorf("HashAlg is not 0 (SHA1). Must be equal 0"), nil
		}
		if pol1.PolicyType != tools.LCPPolicyTypeAny && pol1.PolicyType != tools.LCPPolicyTypeList {
			return false, fmt.Errorf("PolicyType is invalid. Have: %d - Want: %d or %d", pol1.PolicyType, tools.LCPPolicyTypeAny, tools.LCPPolicyTypeList), nil
		}
		if pol1.SINITMinVersion == 0 {
			return false, fmt.Errorf("siNITMinVersion is invalid. Must be greater than 0"), nil
		}
		if pol1.PolicyType == tools.LCPPolicyTypeList && pol1.PolicyControl == 0 {
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
		if pol2.Version < tools.LCPPolicyVersion3 {
			return false, fmt.Errorf("wrong policy version. Have %v - Want: %v", pol2.Version, tools.LCPPolicyVersion3), nil
		}
		if pol2.HashAlg != p.LCPHash {
			return false, fmt.Errorf("HashAlg has invalid value"), nil
		}
		if pol2.PolicyType != tools.LCPPolicyTypeAny && pol1.PolicyType != tools.LCPPolicyTypeList {
			return false, fmt.Errorf("PolicyType is invalid. Have: %d - Want: %d or %d", pol1.PolicyType, tools.LCPPolicyTypeAny, tools.LCPPolicyTypeList), nil
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
func POIndexHasValidLCP(txtAPI hwapi.LowLevelHardwareInterfaces, p *PreSet) (bool, error, error) {
	var pol1 *tools.LCPPolicy
	var pol2 *tools.LCPPolicy2
	emptyHash := make([]byte, 20)
	tpmCon, err := txtAPI.NewTPM()
	if err != nil {
		return false, fmt.Errorf("no TPM connection"), nil
	}
	defer tpmCon.Close()
	switch tpmCon.Version {
	case hwapi.TPMVersion12:
		_, err := txtAPI.ReadNVPublic(tpmCon, tpm12POIndex)
		if err != nil {
			if strings.Contains(err.Error(), tpm12NVIndexNotSet) {
				return true, fmt.Errorf("PO Index not set"), nil
			}
			return false, nil, err
		}
		data, err := txtAPI.NVReadValue(tpmCon, tpm12POIndex, "", tpm12POIndexSize, 0)
		if err != nil {
			return true, err, nil
		}
		pol1, pol2, err = tools.ParsePolicy(data)
		if err != nil {
			return false, nil, err
		}
	case hwapi.TPMVersion20:
		var d tpm2.NVPublic
		var raw []byte
		var err error
		raw, err = txtAPI.ReadNVPublic(tpmCon, tpm20POIndex)
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

		data, err := txtAPI.NVReadValue(tpmCon, tpm20POIndex, "", uint32(size), tpm20POIndex)
		if err != nil {
			return false, fmt.Errorf("unable to read NV value: %w", err), nil
		}
		pol1, pol2, err = tools.ParsePolicy(data)
		if err != nil {
			return false, nil, err
		}
	}
	if pol1 != nil {
		if pol1.Version >= tools.LCPPolicyVersion2 {
			return false, fmt.Errorf("invalid policy version. Have %v - Want: smaller %v", pol1.Version, tools.LCPPolicyVersion2), nil
		}
		if pol1.HashAlg != 0 {
			return false, fmt.Errorf("HashAlg is invalid. Must be equal 0"), nil
		}
		if pol1.PolicyType != tools.LCPPolicyTypeAny && pol1.PolicyType != tools.LCPPolicyTypeList {
			return false, fmt.Errorf("PolicyType is invalid. Have: %d - Want: %d or %d", pol1.PolicyType, tools.LCPPolicyTypeAny, tools.LCPPolicyTypeList), nil
		}
		if pol1.SINITMinVersion == 0 {
			return false, fmt.Errorf("siNITMinVersion is invalid. Must be greater than 0"), nil
		}
		if pol1.PolicyType == tools.LCPPolicyTypeList && pol1.PolicyControl == 0 {
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
		if pol2.Version < tools.LCPPolicyVersion3 {
			return false, fmt.Errorf("wrong lcp policy version. Have %v - Want: %v", pol2.Version, tools.LCPPolicyVersion3), nil
		}
		if pol2.HashAlg != p.LCPHash {
			return false, fmt.Errorf("HashAlg has invalid value"), nil
		}
		if pol2.PolicyType != tools.LCPPolicyTypeAny && pol1.PolicyType != tools.LCPPolicyTypeList {
			return false, fmt.Errorf("PolicyType is invalid. Have: %d - Want: %d or %d", pol1.PolicyType, tools.LCPPolicyTypeAny, tools.LCPPolicyTypeList), nil
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
func PCR0IsSet(txtAPI hwapi.LowLevelHardwareInterfaces, p *PreSet) (bool, error, error) {
	tpmCon, err := txtAPI.NewTPM()
	if err != nil {
		return false, fmt.Errorf("no TPM connection"), nil
	}
	defer tpmCon.Close()
	pcr, err := txtAPI.ReadPCR(tpmCon, 0)
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

func readPSLCPPolicy(txtAPI hwapi.LowLevelHardwareInterfaces) (*tools.LCPPolicy, *tools.LCPPolicy2, error) {
	var pol1 *tools.LCPPolicy
	var pol2 *tools.LCPPolicy2
	tpmCon, err := txtAPI.NewTPM()
	if err != nil {
		return nil, nil, fmt.Errorf("no TPM connection")
	}
	defer tpmCon.Close()
	switch tpmCon.Version {
	case hwapi.TPMVersion12:
		data, err := txtAPI.NVReadValue(tpmCon, tpm12PSIndex, "", tpm12PSIndexSize, 0)
		if err != nil {
			if strings.Contains(err.Error(), tpm12NVIndexNotSet) {
				return nil, nil, err
			}
			return nil, nil, err
		}
		pol1, pol2, err = tools.ParsePolicy(data)
		if err != nil {
			return nil, nil, err
		}
	case hwapi.TPMVersion20:
		var d tpm2.NVPublic
		var raw []byte
		var err error
		raw, err = txtAPI.ReadNVPublic(tpmCon, tpm20PSIndex)
		if err != nil {
			if strings.Contains(err.Error(), tpm2NVPublicNotSet) {
				return nil, nil, fmt.Errorf("PS index not set")
			}
			return nil, nil, err
		}
		buf := bytes.NewReader(raw)
		err = binary.Read(buf, binary.BigEndian, &d.NVIndex)
		if err != nil {
			return nil, nil, err
		}
		err = binary.Read(buf, binary.BigEndian, &d.NameAlg)
		if err != nil {
			return nil, nil, err
		}
		err = binary.Read(buf, binary.BigEndian, &d.Attributes)
		if err != nil {
			return nil, nil, err
		}
		// Helper valiable hashSize- go-tpm2 does not implement proper structure
		var hashSize uint16
		err = binary.Read(buf, binary.BigEndian, &hashSize)
		if err != nil {
			return nil, nil, err
		}
		// Uses hashSize to make the right sized slice to read the hash
		hashData := make([]byte, hashSize)
		err = binary.Read(buf, binary.BigEndian, &hashData)
		if err != nil {
			return nil, nil, err
		}
		err = binary.Read(buf, binary.BigEndian, &d.DataSize)
		if err != nil {
			return nil, nil, err
		}
		size := uint16(crypto.Hash(d.NameAlg).Size()) + tpm20PSIndexBaseSize

		data, err := txtAPI.NVReadValue(tpmCon, tpm20PSIndex, "", uint32(size), tpm20PSIndex)
		if err != nil {
			return nil, nil, fmt.Errorf("unable to read NV value: %w", err)
		}
		pol1, pol2, err = tools.ParsePolicy(data)
		if err != nil {
			return nil, nil, err
		}
	}
	return pol1, pol2, nil
}

// NPWModeIsNotSetInPS checks if NPW is activated or not
func NPWModeIsNotSetInPS(txtAPI hwapi.LowLevelHardwareInterfaces, p *PreSet) (bool, error, error) {
	pol1, pol2, err := readPSLCPPolicy(txtAPI)
	if err != nil {
		return false, err, nil
	}
	if pol1 != nil {
		if pol1.ParsePolicyControl().NPW {
			return false, fmt.Errorf("NPW mode is activated"), nil
		}
	}
	if pol2 != nil {
		if pol2.ParsePolicyControl2().NPW {
			return false, fmt.Errorf("NPW mode is activated"), nil
		}
	}
	return true, nil, nil
}

// TXTModeValid checks if TXT is in valid mode
func TXTModeValid(txtAPI hwapi.LowLevelHardwareInterfaces, p *PreSet) (bool, error, error) {
	pol1, pol2, err := readPSLCPPolicy(txtAPI)
	if err != nil {
		return false, nil, err
	}
	switch p.TXTMode {
	case tools.AutoPromotion:
		if pol1 != nil && pol1.PolicyType == tools.LCPPolicyTypeAny {
			return true, nil, nil
		}
		if pol2 != nil && pol2.PolicyType == tools.LCPPolicyTypeAny {
			return true, nil, nil
		}
	case tools.SignedPolicy:
		if pol1 != nil && pol1.PolicyType == tools.LCPPolicyTypeList {
			return true, nil, nil
		}
		if pol2 != nil && pol2.PolicyType == tools.LCPPolicyTypeList {
			return true, nil, nil
		}
	}
	return false, nil, fmt.Errorf("couldn't validate TXT mode of operation")
}
