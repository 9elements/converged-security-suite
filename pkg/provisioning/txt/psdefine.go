package txt

import (
	"fmt"
	"io"

	tpm2 "github.com/google/go-tpm/tpm2"
)

// DefinePSIndexTPM20 creates the PS index for TPM 2.0
func DefinePSIndexTPM20(rw io.ReadWriter, passHash []byte) error {
	_, err := tpm2.NVReadPublic(rw, tpm2PSIndexDef.NVIndex)
	if err == nil {
		return fmt.Errorf("PS index already defined in TPM 2.0 - Delete first")
	}
	psPolicyHash, err := getPSPolicyHash(rw, passHash)
	if err != nil {
		return fmt.Errorf("getPSPolicyHash() failed: %v", err)
	}
	tpm2PSIndexDef.AuthPolicy = psPolicyHash
	authArea := tpm2.AuthCommand{Session: tpm2.HandlePasswordSession, Attributes: tpm2.AttrContinueSession, Auth: tpm2.EmptyAuth}
	err = tpm2.NVDefineSpaceEx(rw, tpm2.HandlePlatform, "", tpm2PSIndexDef, authArea)
	if err != nil {
		return fmt.Errorf("NVDefineSpaceEx() failed: %v", err)
	}
	fmt.Println("PS index defined successfully")
	return nil
}

// DefinePSIndexTPM12 creates the PS index for TPM 1.2
func DefinePSIndexTPM12(rw io.ReadWriter) error {
	return fmt.Errorf("Not implemented yet")
}
