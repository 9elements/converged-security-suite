package provisioning

import (
	"fmt"
	"io"

	tools "github.com/9elements/converged-security-suite/pkg/tools"
	tpm2 "github.com/google/go-tpm/tpm2"
	tpmutil "github.com/google/go-tpm/tpmutil"
)

var (
	emptyPW string
)

// ProvisionTPM20 generates and provision the TPM 2.0 module and return the PS policyHash
func ProvisionTPM20(rw io.ReadWriter, delHash, writeHash []byte, lcppol *tools.LCPPolicy2) (*[32]byte, error) {
	var ret [32]byte
	_, err := tpm2.NVReadPublic(rw, tpm2PSIndexDef.NVIndex)
	if err == nil {
		return nil, fmt.Errorf("PS index already defined in TPM 2.0 - Undefine first")
	}
	psPolicyHash, err := getPSPolicyHash(rw, delHash, writeHash)
	if err != nil {
		return nil, fmt.Errorf("getPSPolicyHash() failed: %v", err)
	}
	if err := definePSIndexTPM20(rw, psPolicyHash); err != nil {
		return nil, fmt.Errorf("definePSIndexTPM20() failed: %v", err)
	}
	if err := writePSPolicy(rw, lcppol, delHash, writeHash); err != nil {
		return nil, fmt.Errorf("writePSPolicy() failed: %v", err)
	}
	if err := defineAUXIndexTPM20(rw); err != nil {
		return nil, fmt.Errorf("defineAUXIndexTPM20() failed: %v", err)
	}
	copy(ret[:], psPolicyHash[:32])
	return &ret, nil
}

func definePSIndexTPM20(rw io.ReadWriter, pspolhash tpmutil.U16Bytes) error {
	psIndexDef := tpm2.NVPublic{
		NVIndex: tpmutil.Handle(0x01C10103),
		NameAlg: tpm2.AlgSHA256,
		Attributes: tpm2.AttrPolicyWrite + tpm2.AttrPolicyDelete +
			tpm2.AttrAuthRead + tpm2.AttrNoDA + tpm2.AttrPlatformCreate,
		AuthPolicy: pspolhash,
		DataSize:   uint16(70),
	}
	authArea := tpm2.AuthCommand{Session: tpm2.HandlePasswordSession, Attributes: tpm2.AttrContinueSession, Auth: []byte(tpm2.EmptyAuth)}
	err := tpm2.NVDefineSpaceEx(rw, tpm2.HandlePlatform, authArea, "", psIndexDef)
	if err != nil {
		return fmt.Errorf("NVDefineSpaceEx() failed: %v", err)
	}
	return nil
}

func defineAUXIndexTPM20(rw io.ReadWriter) error {
	authArea := tpm2.AuthCommand{Session: tpm2.HandlePasswordSession, Attributes: tpm2.AttrContinueSession, Auth: []byte(tpm2.EmptyAuth)}
	err := tpm2.NVDefineSpaceEx(rw, tpm2.HandlePlatform, authArea, "", tpm20AUXIndexDef)
	if err != nil {
		return fmt.Errorf("NVDefineSpaceEx() failed: %v", err)
	}
	return nil
}

func getPSPolicyHash(rw io.ReadWriter, delHash, writeHash []byte) ([]byte, error) {
	zeroHash := make([]byte, len(delHash))
	delBranch, err := constructDelBranch(rw, delHash, zeroHash)
	if err != nil {
		return nil, fmt.Errorf("constructDelBranch() failed: %v", err)
	}
	writeBranch, err := constructWriteBranch(rw, writeHash, zeroHash)
	if err != nil {
		return nil, fmt.Errorf("constructWriteBranch() failed: %v", err)
	}

	psPol, err := mergeToPSPolicy(rw, delBranch, writeBranch)
	if err != nil {
		return nil, fmt.Errorf("mergeToPSPolicy() failed: %v", err)
	}
	return psPol, nil
}

func constructDelBranch(rw io.ReadWriter, delHash, zeroHash []byte) ([]byte, error) {
	sess, _, err := tpm2.StartAuthSession(rw, tpm2.HandleNull, tpm2.HandleNull, make([]byte, 16), nil, tpm2.SessionPolicy, tpm2.AlgNull, tpm2.AlgSHA256)
	if err != nil {
		return nil, err
	}
	hashData := tpm2.TPMLDigest{Digests: []tpmutil.U16Bytes{delHash, zeroHash}}
	err = tpm2.PolicyOr(rw, sess, hashData)
	if err != nil {
		return nil, err
	}
	err = tpm2.PolicyCommandCode(rw, sess, tpm2.CmdNVUndefineSpaceSpecial)
	if err != nil {
		return nil, err
	}
	data, err := tpm2.PolicyGetDigest(rw, sess)
	if err != nil {
		return nil, err
	}
	err = tpm2.FlushContext(rw, sess)
	if err != nil {
		return nil, err
	}
	return data, nil
}

func constructWriteBranch(rw io.ReadWriter, writeHash, zeroHash []byte) ([]byte, error) {
	sess, _, err := tpm2.StartAuthSession(rw, tpm2.HandleNull, tpm2.HandleNull, make([]byte, 16), nil, tpm2.SessionPolicy, tpm2.AlgNull, tpm2.AlgSHA256)
	if err != nil {
		return nil, err
	}
	hashData := tpm2.TPMLDigest{Digests: []tpmutil.U16Bytes{writeHash, zeroHash}}
	err = tpm2.PolicyOr(rw, sess, hashData)
	if err != nil {
		return nil, err
	}
	data, err := tpm2.PolicyGetDigest(rw, sess)
	if err != nil {
		return nil, err
	}
	err = tpm2.FlushContext(rw, sess)
	if err != nil {
		return nil, err
	}
	return data, nil
}

func mergeToPSPolicy(rw io.ReadWriter, delPol, writePol []byte) ([]byte, error) {
	sess, _, err := tpm2.StartAuthSession(rw, tpm2.HandleNull, tpm2.HandleNull, make([]byte, 16), nil, tpm2.SessionTrial, tpm2.AlgNull, tpm2.AlgSHA256)
	if err != nil {
		return nil, err
	}
	hashData := tpm2.TPMLDigest{Digests: []tpmutil.U16Bytes{delPol, writePol}}
	err = tpm2.PolicyOr(rw, sess, hashData)
	if err != nil {
		return nil, fmt.Errorf("PolicyOr() failed: %v, len(delPol): %v, len(writePol): %v", err, delPol, writePol)
	}
	data, err := tpm2.PolicyGetDigest(rw, sess)
	if err != nil {
		return nil, err
	}
	err = tpm2.FlushContext(rw, sess)
	if err != nil {
		return nil, err
	}
	return data, nil
}

// ProvisionTPM12 generates and provision the TPM 1.2 module
func ProvisionTPM12(rw io.ReadWriter) error {
	return fmt.Errorf("Not implemented yet")
}

func writePSPolicy(rw io.ReadWriter, lcppol *tools.LCPPolicy2, delHash, writeHash []byte) error {
	zeroHash := make([]byte, 32)
	delPol, err := constructDelBranch(rw, delHash, zeroHash)
	if err != nil {
		return fmt.Errorf("constructDelBranch() failed: %v", err)
	}
	writePol, err := constructWriteBranch(rw, writeHash, zeroHash)
	if err != nil {
		return fmt.Errorf("constructWriteBranch() failed: %v", err)
	}
	sess, _, err := tpm2.StartAuthSession(rw, tpm2.HandleNull, tpm2.HandleNull, make([]byte, 16), nil, tpm2.SessionPolicy, tpm2.AlgNull, tpm2.AlgSHA256)
	if err != nil {
		return fmt.Errorf("StartAuthSession in writePSPolicy failed: %v", err)
	}

	a := tpm2.TPMLDigest{Digests: []tpmutil.U16Bytes{writeHash, zeroHash}}
	b := tpm2.TPMLDigest{Digests: []tpmutil.U16Bytes{delPol, writePol}}

	err = tpm2.PolicyOr(rw, sess, a)
	if err != nil {
		return fmt.Errorf("writePSPolicy() failed at PolicyOR1: %v", err)
	}
	err = tpm2.PolicyOr(rw, sess, b)
	if err != nil {
		return fmt.Errorf("writePSPolicy() failed at PolicyOR2: %v", err)
	}
	lcpbytes, err := tpmutil.Pack(lcppol)
	if err != nil {
		return err
	}
	lcpraw, err := tpmutil.Pack(lcpbytes)
	if err != nil {
		return err
	}
	authArea := tpm2.AuthCommand{
		Session:    sess,
		Attributes: tpm2.AttrContinueSession,
	}
	err = tpm2.NVWriteEx(rw, tpm2PSIndexDef.NVIndex, tpm2PSIndexDef.NVIndex, authArea, lcpraw, 0)
	if err != nil {
		return fmt.Errorf("NVWrite in writePSPolicy failed: %v", err)
	}
	lcppol.PrettyPrint()
	return nil
}
