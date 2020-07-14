package provisioning

import (
	"fmt"
	"io"

	tpm2 "github.com/google/go-tpm/tpm2"
	tpmutil "github.com/google/go-tpm/tpmutil"
)

// DeletePSindexTPM20 deletes the PS index on TPM 2.0
func DeletePSindexTPM20(rw io.ReadWriter, delHash []byte) error {
	zeroHash := make([]byte, len(delHash))
	sess, _, err := tpm2.StartAuthSession(rw, tpm2.HandleNull, tpm2.HandleNull, make([]byte, 16), nil, tpm2.SessionPolicy, tpm2.AlgNull, tpm2.AlgSHA256)
	if err != nil {
		return nil
	}
	delhashraw, err := tpmutil.Pack(delHash)
	if err != nil {
		return err
	}
	zerohashraw, err := tpmutil.Pack(zeroHash)
	if err != nil {
		return err
	}
	delhashdata := tpmutil.U16Bytes(delhashraw)
	zeorhashdata := tpmutil.U16Bytes(zerohashraw)
	err = tpm2.PolicyOr(rw, sess, tpm2.TPMLDigest{Count: uint32(2), Digests: []tpmutil.U16Bytes{delhashdata, zeorhashdata}})
	if err != nil {
		return err
	}
	err = tpm2.NVUndefineSpaceSpecial(rw, tpm2PSIndexDef.NVIndex, sess)
	if err != nil {
		return err
	}
	err = tpm2.FlushContext(rw, sess)
	return err
}

// DeletePSIndexTPM12 deletes the PS index on TPM 1.2
func DeletePSIndexTPM12(rw io.ReadWriter) error {
	return fmt.Errorf("Not implemented yet")
}
