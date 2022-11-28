package tpm

import "github.com/9elements/converged-security-suite/v2/pkg/bootflow/types"

type Command interface {
	apply(*TPM) error
	LogString() string
}

type CommandLogEntry struct {
	Command     Command
	CauseAction types.Action
}

type CommandLog []CommandLogEntry

func newCommandLogEntry(cmd Command, causeAction types.Action) CommandLogEntry {
	return CommandLogEntry{
		Command:     cmd,
		CauseAction: causeAction,
	}
}
