package provisioning

import (
	"fmt"
	"io"

	tools "github.com/9elements/converged-security-suite/pkg/tools"
)

// DeleteAUXindexTPM20 deletes the AUX index on TPM 2.0
func DeleteAUXindexTPM20(rw io.ReadWriter, psPol *tools.LCPPolicy2, writeHash, delHash []byte) error {
	if (1 >> (psPol.PolicyControl & tools.LCPPolicyControlAuxDelete)) != 0 {
		return fmt.Errorf("AuxDelete not set in LCP Policy")
	}
	err := writePSPolicy(rw, psPol, delHash, writeHash)
	if err != nil {
		return err
	}
	return nil
}

// DeleteAUXIndexTPM12 deletes the AUX index on TPM 1.2
func DeleteAUXIndexTPM12(rw io.ReadWriter) error {
	return fmt.Errorf("Not implemented yet")
}
