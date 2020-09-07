package txt

import (
	"fmt"
	"io"

	tpm2 "github.com/google/go-tpm/tpm2"
)

// DefineAUXIndexTPM20 defines the AUX index on TPM 2.0
func DefineAUXIndexTPM20(rw io.ReadWriter) error {
	_, err := tpm2.NVReadPublic(rw, tpm20AUXIndexDef.NVIndex)
	if err == nil {
		return fmt.Errorf("AUX index already defined in TPM 2.0 - Delete first")
	}
	authArea := tpm2.AuthCommand{Session: tpm2.HandlePasswordSession, Attributes: tpm2.AttrContinueSession, Auth: []byte(tpm2.EmptyAuth)}
	err = tpm2.NVDefineSpaceEx(rw, tpm2.HandlePlatform, "", tpm20AUXIndexDef, authArea)
	if err != nil {
		return fmt.Errorf("NVDefineSpaceEx() failed: %v", err)
	}
	fmt.Println("AUX index defined successfully")
	return nil
}

// DefineAUXIndexTPM12 defines the AUX index on TPM 1.2
func DefineAUXIndexTPM12(rw io.ReadWriter) error {
	return fmt.Errorf("Not implemented yet")
}
