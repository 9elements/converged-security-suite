package tpm

import (
	"context"
	"fmt"
	"strings"

	"github.com/9elements/converged-security-suite/v2/pkg/bootflow/lib/format"
	"github.com/9elements/converged-security-suite/v2/pkg/bootflow/types"
)

// Command is a serializable command that could be "sent" (applied) to TPM.
type Command interface {
	// Apply applies the changes themselves to the given *TPM (not including appending CommandLog).
	//
	// Do not use this method directly unless you know what are you doing,
	// use (*TPM).TPMExecute instead.
	Apply(context.Context, *TPM) error

	// LogString formats the entry for CommandLog.
	LogString() string
}

// Commands is a slice of Command-s
type Commands []Command

// apply implements Command.
func (s Commands) Apply(ctx context.Context, tpm *TPM) error {
	for idx, cmd := range s {
		if err := cmd.Apply(ctx, tpm); err != nil {
			return fmt.Errorf("unable to apply command #%d '%T': %w", idx, cmd, err)
		}
	}
	return nil
}

// LogString implements Command.
func (s Commands) LogString() string {
	result := make([]string, 0, len(s))
	for _, cmd := range s {
		result = append(result, cmd.LogString())
	}
	return strings.Join(result, ", ")
}

// CauseCoordinates defines the coordinates of the Action in a Flow which caused the Command.
type CauseCoordinates = types.ActionCoordinates

// CauseAction defines the Action which caused the Command.
type CauseAction = types.Action

// CommandLogEntry is a log entry of a Command.
type CommandLogEntry struct {
	Command
	CauseCoordinates
	CauseAction
}

// String implements fmt.Stringer.
func (entry CommandLogEntry) String() string {
	return entry.Command.LogString()
}

func newCommandLogEntry(
	cmd Command,
	causeCoords types.ActionCoordinates,
	causeAction types.Action,
) CommandLogEntry {
	return CommandLogEntry{
		Command:          cmd,
		CauseCoordinates: causeCoords,
		CauseAction:      causeAction,
	}
}

// CommandLog is a log of Command-s executed by the TPM.
type CommandLog []CommandLogEntry

// Commands returns the list of raw Command-s.
func (s CommandLog) Commands() Commands {
	result := make(Commands, 0, len(s))
	for _, entry := range s {
		result = append(result, entry.Command)
	}
	return result
}

// String implements fmt.Stringer
func (s CommandLog) String() string {
	var result strings.Builder
	for idx, e := range s {
		result.WriteString(fmt.Sprintf("%d. %s\n", idx, format.NiceString(e)))
	}
	return result.String()
}
