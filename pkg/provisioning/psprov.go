package provisioning

import (
	"crypto"
	"fmt"
	"io"

	tpm2 "github.com/google/go-tpm/tpm2"
	tpmutil "github.com/google/go-tpm/tpmutil"
)

var (
	emptyPW string
)

// ProvisionTPM20 generates and provision the TPM 2.0 module
func ProvisionTPM20(rw io.ReadWriter, delHash, writeHash []byte, hashAlg crypto.Hash) ([]byte, *crypto.Hash, error) {
	_, err := tpm2.NVReadPublic(rw, tpm2PSIndexDef.NVIndex)
	if err == nil {
		return nil, nil, fmt.Errorf("PS index already defined in TPM 2.0 - Undefine first")
	}
	_, err = tpm2.NVReadPublic(rw, tpm20AUXIndexDef.NVIndex)
	if err == nil {
		return nil, nil, fmt.Errorf("AUX index already defined in TPM2.0 - Undefine first")
	}
	psPolicyHash, err := getPSPolicyHash(rw, delHash, writeHash)
	if err != nil {
		return nil, nil, err
	}
	if err := definePSIndexTPM20(rw, psPolicyHash, hashAlg); err != nil {
		return nil, nil, err
	}
	/*
		Write LCP Policy to PS index here
	*/
	if err := defineAUXIndexTPM20(rw); err != nil {
		return nil, nil, err
	}

	return psPolicyHash, &hashAlg, nil
}

func definePSIndexTPM20(rw io.ReadWriter, pspolhash []byte, hashAlg crypto.Hash) error {
	tpm2PSIndexDef.AuthPolicy = pspolhash
	tpm2PSIndexDef.NameAlg = tpm2.Algorithm(hashAlg)

	err := tpm2.NVDefineSpaceEx(tpmCon.RWC, tpm2.HandleOwner, emptyPW, emptyPW, tpm2PSIndexDef)
	return err
}

func defineAUXIndexTPM20(rw io.ReadWriter) error {
	return tpm2.NVDefineSpaceEx(rw, tpm2.HandleOwner, emptyPW, emptyPW, tpm20AUXIndexDef)
}

func getPSPolicyHash(rw io.ReadWriter, delHash, writeHash []byte) ([]byte, error) {
	zeroHash := make([]byte, len(delHash))
	delBranch, err := constructDelBranch(rw, delHash, zeroHash)
	if err != nil {
		return nil, err
	}
	writeBranch, err := constructWriteBranch(rw, writeHash, zeroHash)
	if err != nil {
		return nil, err
	}

	psPol, err := mergeToPSPolicy(rw, delBranch, writeBranch)
	if err != nil {
		return nil, err
	}
	return psPol, nil
}

func constructDelBranch(rw io.ReadWriter, delHash, zeroHash []byte) ([]byte, error) {
	sess, _, err := tpm2.StartAuthSession(tpmCon.RWC, tpm2.HandleNull, tpm2.HandleNull, make([]byte, 16), nil, tpm2.SessionPolicy, tpm2.AlgNull, tpm2.AlgSHA256)
	if err != nil {
		return nil, err
	}
	delhashraw, err := tpmutil.Pack(delHash)
	if err != nil {
		return nil, err
	}
	zerohashraw, err := tpmutil.Pack(zeroHash)
	if err != nil {
		return nil, err
	}
	delhashdata := tpmutil.U16Bytes(delhashraw)
	zeorhashdata := tpmutil.U16Bytes(zerohashraw)
	err = tpm2.PolicyOr(rw, sess, tpm2.TPMLDigest{Count: uint32(2), Digests: []tpmutil.U16Bytes{delhashdata, zeorhashdata}})
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
	writehashraw, err := tpmutil.Pack(writeHash)
	if err != nil {
		return nil, err
	}
	zerohashraw, err := tpmutil.Pack(zeroHash)
	if err != nil {
		return nil, err
	}
	writehashdata := tpmutil.U16Bytes(writehashraw)
	zeorhashdata := tpmutil.U16Bytes(zerohashraw)
	err = tpm2.PolicyOr(rw, sess, tpm2.TPMLDigest{Count: uint32(2), Digests: []tpmutil.U16Bytes{writehashdata, zeorhashdata}})
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
	sess, _, err := tpm2.StartAuthSession(rw, tpm2.HandleNull, tpm2.HandleNull, make([]byte, 16), nil, tpm2.SessionPolicy, tpm2.AlgNull, tpm2.AlgSHA256)
	if err != nil {
		return nil, err
	}
	delhashraw, err := tpmutil.Pack(delPol)
	if err != nil {
		return nil, err
	}
	writehashraw, err := tpmutil.Pack(writePol)
	if err != nil {
		return nil, err
	}
	delhashdata := tpmutil.U16Bytes(delhashraw)
	writehashdata := tpmutil.U16Bytes(writehashraw)
	err = tpm2.PolicyOr(rw, sess, tpm2.TPMLDigest{Count: uint32(2), Digests: []tpmutil.U16Bytes{delhashdata, writehashdata}})
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

// ProvisionTPM12 generates and provision the TPM 1.2 module
func ProvisionTPM12(rw io.ReadWriter) error {
	return fmt.Errorf("Not implemented yet")
}
