package txt

import (
	"fmt"
	"io"

	tools "github.com/9elements/converged-security-suite/v2/pkg/tools"

	log "github.com/sirupsen/logrus"
)

// DeleteAUXindexTPM20 deletes the AUX index on TPM 2.0
func DeleteAUXindexTPM20(rw io.ReadWriter, pol *tools.LCPPolicy2, passHash []byte) error {
	if !pol.ParsePolicyControl2().AuxDelete {
		return fmt.Errorf("AuxDelete not set in LCP Policy")
	}
	err := WritePSIndexTPM20(rw, pol, passHash)
	if err != nil {
		return err
	}
	log.Info("AUX index deletion in progress, please reboot machine")
	return nil
}

// DeleteAUXIndexTPM12 deletes the AUX index on TPM 1.2
func DeleteAUXIndexTPM12(rw io.ReadWriter) error {
	return fmt.Errorf("not implemented yet")
}
