//go:build none
// +build none

package trustchains

import (
	pcrtypes "github.com/9elements/converged-security-suite/v2/pkg/pcr/types"
)

// This files is used only to provide hints to the "goplantuml" tool

type TPM struct {
	TPMEventLog
	PCRValues
}

type TPMEventLogEntry struct {
	PCRID
}
