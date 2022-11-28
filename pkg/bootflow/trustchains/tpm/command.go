package tpm

import (
	"context"
	"fmt"
	"strings"

	"github.com/9elements/converged-security-suite/v2/pkg/bootflow/types"
)

type Command interface {
	apply(context.Context, *TPM) error
	LogString() string
}

type Commands []Command

func (s Commands) apply(ctx context.Context, tpm *TPM) error {
	for idx, cmd := range s {
		if err := cmd.apply(ctx, tpm); err != nil {
			return fmt.Errorf("unable to apply command #%d '%T': %w", idx, cmd, err)
		}
	}
	return nil
}

func (s Commands) LogString() string {
	result := make([]string, 0, len(s))
	for _, cmd := range s {
		result = append(result, cmd.LogString())
	}
	return strings.Join(result, ", ")
}

type CauseCoordinates = types.ActionCoordinates

type CommandLogEntry struct {
	Command
	CauseCoordinates
}

func newCommandLogEntry(
	cmd Command,
	causeCoords types.ActionCoordinates,
) CommandLogEntry {
	return CommandLogEntry{
		Command:          cmd,
		CauseCoordinates: causeCoords,
	}
}

type CommandLog []CommandLogEntry

func (s CommandLog) Commands() Commands {
	result := make(Commands, 0, len(s))
	for _, entry := range s {
		result = append(result, entry.Command)
	}
	return result
}
