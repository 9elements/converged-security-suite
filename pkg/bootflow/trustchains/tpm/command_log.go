package tpm

import (
	"fmt"

	"github.com/9elements/converged-security-suite/v2/pkg/bootflow/types"
	"github.com/google/go-tpm/tpm2"
)

type CommandLog []CommandLogEntry

type CommandLogEntry interface {
	LogString() string
}

type CommandLogEntryInit struct {
	Locality uint8
}

func (entry CommandLogEntryInit) LogString() string {
	return fmt.Sprintf("TPMInit(%d)", entry.Locality)
}

func (entry CommandLogEntryInit) GoString() string {
	return entry.LogString()
}

type CommandLogEntryExtend struct {
	PCRIndex PCRID
	HashAlgo tpm2.Algorithm
	Digest   Digest

	// CauseAction holds the original action, which triggered this TPMExtend. The original
	// data contributed to `Digest` should be accessible through this CauseAction.
	CauseAction types.Action
}

func (entry CommandLogEntryExtend) LogString() string {
	return fmt.Sprintf("TPMExtend(%d, %s, %X)", entry.PCRIndex, entry.HashAlgo, entry.Digest)
}

func (entry CommandLogEntryExtend) GoString() string {
	return entry.LogString()
}
