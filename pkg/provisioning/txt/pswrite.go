package txt

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"

	tools "github.com/9elements/converged-security-suite/v2/pkg/tools"
	tpm2 "github.com/google/go-tpm/tpm2"
	tpmutil "github.com/google/go-tpm/tpmutil"
)

// WritePSIndexTPM20 writes the LCP Policy2 into the PS index of TPM 2.0
func WritePSIndexTPM20(rw io.ReadWriter, lcppol *tools.LCPPolicy2, passHash []byte) error {
	zeroHash := make([]byte, 32)
	delPol, err := constructDelBranch(rw, passHash, zeroHash)
	if err != nil {
		return fmt.Errorf("constructDelBranch() failed: %v", err)
	}
	writePol, err := constructWriteBranch(rw, passHash, zeroHash)
	if err != nil {
		return fmt.Errorf("constructWriteBranch() failed: %v", err)
	}
	sess, _, err := tpm2.StartAuthSession(rw, tpm2.HandleNull, tpm2.HandleNull, make([]byte, 16), nil, tpm2.SessionPolicy, tpm2.AlgNull, tpm2.AlgSHA256)
	if err != nil {
		return fmt.Errorf("StartAuthSession in writePSPolicy failed: %v", err)
	}

	a := tpm2.TPMLDigest{Digests: []tpmutil.U16Bytes{passHash, zeroHash}}
	b := tpm2.TPMLDigest{Digests: []tpmutil.U16Bytes{delPol, writePol}}

	err = tpm2.PolicyOr(rw, sess, a)
	if err != nil {
		return fmt.Errorf("writePSPolicy() failed at PolicyOR1: %v", err)
	}
	err = tpm2.PolicyOr(rw, sess, b)
	if err != nil {
		return fmt.Errorf("writePSPolicy() failed at PolicyOR2: %v", err)
	}
	authArea := tpm2.AuthCommand{
		Session:    sess,
		Attributes: tpm2.AttrContinueSession,
	}
	var buf bytes.Buffer
	var pol tools.LCPPolicy2
	pol = *lcppol
	err = binary.Write(&buf, binary.LittleEndian, pol)
	if err != nil {
		return fmt.Errorf("NVWrite in writePSPolicy failed: %v", err)
	}
	err = tpm2.NVWriteEx(rw, tpm2PSIndexDef.NVIndex, tpm2PSIndexDef.NVIndex, authArea, buf.Bytes(), 0)
	if err != nil {
		return fmt.Errorf("NVWrite in writePSPolicy failed: %v", err)
	}
	fmt.Println("PS index updated successfully")
	return nil
}

// WritePSIndexTPM12 writes the LCP Policy into the PS index of TPM 1.2
func WritePSIndexTPM12(rw io.ReadWriter, lcppol *tools.LCPPolicy) error {
	return fmt.Errorf("Not implemented yet")
}
