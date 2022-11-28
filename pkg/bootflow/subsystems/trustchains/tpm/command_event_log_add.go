package tpm

import (
	"context"
	"fmt"
	"strings"
)

// CommandEventLogAdd is a Command which adds an entry to TPM Event Log.
type CommandEventLogAdd struct {
	CommandExtend
	Data []byte
}

var _ Command = (*CommandEventLogAdd)(nil)

// NewCommandEventLogAdd returns a new instance of CommandEventLogAdd
func NewCommandEventLogAdd(
	cmdExtend CommandExtend,
	data []byte,
) *CommandEventLogAdd {
	return &CommandEventLogAdd{
		CommandExtend: cmdExtend,
		Data:          data,
	}
}

// LogString formats the entry for CommandLog.
func (cmd *CommandEventLogAdd) LogString() string {
	extendData := strings.Trim(strings.ReplaceAll(cmd.CommandExtend.String(), "TPMExtend", ""), "()")
	if cmd.Data != nil {
		return fmt.Sprintf("TPMEventLogAdd(%v, Data: 0x%X)", extendData, cmd.Data)
	}
	return fmt.Sprintf("TPMEventLogAdd(%s)", extendData)
}

// String implements fmt.Stringer.
func (cmd *CommandEventLogAdd) String() string {
	return cmd.LogString()
}

// apply implements Command.
func (cmd *CommandEventLogAdd) apply(_ context.Context, tpm *TPM) error {
	tpm.EventLog.Add(cmd.CommandExtend, cmd.Data)
	return nil
}
