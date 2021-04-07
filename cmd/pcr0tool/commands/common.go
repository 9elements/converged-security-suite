package commands

import (
	"fmt"
	"github.com/9elements/converged-security-suite/v2/pkg/pcr"
	"github.com/9elements/converged-security-suite/v2/pkg/tpmdetection"
)

// FlowCommandLineValues returns a human readable array of all supported pcr attestation flows
func FlowCommandLineValues() string {
	var result string
	for _, f := range pcr.Flows {
		if len(result) > 0 {
			result += ", "
		}
		result += fmt.Sprintf("'%s'", f.String())
	}
	return result
}

// TPMTypeCommandLineValues returns a human readable array of all supported tpm devices
func TPMTypeCommandLineValues() string {
	var result string
	for _, f := range tpmdetection.ActiveTypes() {
		if len(result) > 0 {
			result += ", "
		}
		result += fmt.Sprintf("'%s'", f.String())
	}
	return result
}
