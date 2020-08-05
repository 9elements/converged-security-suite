package provisioning

import (
	"fmt"
	"io"
)

// DeleteAUXindexTPM20 deletes the AUX index on TPM 2.0
func DeleteAUXindexTPM20(rw io.ReadWriter, writeHash []byte) error {
	return fmt.Errorf("Not implemented yet")
}

// DeleteAUXIndexTPM12 deletes the AUX index on TPM 1.2
func DeleteAUXIndexTPM12(rw io.ReadWriter) error {
	return fmt.Errorf("Not implemented yet")
}
