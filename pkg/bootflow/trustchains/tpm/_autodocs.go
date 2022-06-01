//go:build none
// +build none

package tpm

import (
	pcrtypes "github.com/9elements/converged-security-suite/v2/pkg/pcr/types"
)

// This files is used only to provide hints to the "goplantuml" tool

type TPM struct {
	EventLog
	PCRValues
}

type EventLogEntry struct {
	PCRID
}
