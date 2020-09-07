package txt

import (
	"fmt"
	"io"

	tpm2 "github.com/google/go-tpm/tpm2"
	tpmutil "github.com/google/go-tpm/tpmutil"
)

func getPSPolicyHash(rw io.ReadWriter, policyHash []byte) ([]byte, error) {
	zeroHash := make([]byte, len(policyHash))
	delBranch, err := constructDelBranch(rw, policyHash, zeroHash)
	if err != nil {
		return nil, fmt.Errorf("constructDelBranch() failed: %v", err)
	}
	writeBranch, err := constructWriteBranch(rw, policyHash, zeroHash)
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
