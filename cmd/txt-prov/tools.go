package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"io/ioutil"
	"strings"

	"github.com/9elements/converged-security-suite/v2/pkg/hwapi"
	"github.com/9elements/converged-security-suite/v2/pkg/tools"
	"github.com/google/go-tpm/tpm"
	"github.com/google/go-tpm/tpm2"
	"golang.org/x/crypto/ssh/terminal"
)

var (
	tpm2LockedResult = "error code 0x22"
)

func readPassphraseHashTPM20() ([]byte, error) {
	fmt.Printf("Now, please type in the password (mandatory): ")
	password, err := terminal.ReadPassword(0)
	if err != nil {
		return []byte{}, err
	}
	fmt.Println()
	hash := sha256.Sum256([]byte(password))
	return hash[:], nil
}

func writePSPolicy2file(policy *tools.LCPPolicy2, filename string) error {
	var buf bytes.Buffer
	var pol tools.LCPPolicy2
	pol = *policy
	err := binary.Write(&buf, binary.LittleEndian, pol)
	if err != nil {
		return err
	}
	if err = ioutil.WriteFile(filename, buf.Bytes(), 0600); err != nil {
		return err
	}
	return nil
}

// IsNVRAMUnlocked checks if NVRAM is locked
func IsNVRAMUnlocked(tpmTss *hwapi.TPM) (bool, error) {
	switch tpmTss.Version {
	case hwapi.TPMVersion12:
		flags, err := tpm.GetPermanentFlags(tpmTss.RWC)
		if err != nil {
			return false, err
		}
		if !flags.NVLocked {
			return true, nil
		}
	case hwapi.TPMVersion20:
		err := tpm2.HierarchyChangeAuth(tpmTss.RWC, tpm2.HandlePlatform, tpm2.AuthCommand{Session: tpm2.HandlePasswordSession, Attributes: tpm2.AttrContinueSession}, string(tpm2.EmptyAuth))
		if err == nil {
			return false, err
		}
		return !strings.Contains(err.Error(), tpm2LockedResult), nil
	}
	return false, fmt.Errorf("TPM version couldn't be determined")
}
