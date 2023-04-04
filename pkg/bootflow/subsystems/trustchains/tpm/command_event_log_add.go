package tpm

import (
	"context"
	"fmt"
	"strings"

	"github.com/9elements/converged-security-suite/v2/pkg/tpmeventlog"
)

// CommandEventLogAdd is a Command which adds an entry to TPM Event Log.
type CommandEventLogAdd struct {
	CommandExtend
	Type tpmeventlog.EventType
	Data []byte
}

var _ Command = (*CommandEventLogAdd)(nil)

// NewCommandEventLogAdd returns a new instance of CommandEventLogAdd
func NewCommandEventLogAdd(
	cmdExtend CommandExtend,
	evType tpmeventlog.EventType,
	data []byte,
) *CommandEventLogAdd {
	return &CommandEventLogAdd{
		CommandExtend: cmdExtend,
		Type:          evType,
		Data:          data,
	}
}

// LogString formats the entry for CommandLog.
func (cmd *CommandEventLogAdd) LogString() string {
	extendData := strings.Trim(strings.ReplaceAll(cmd.CommandExtend.String(), "TPMExtend", ""), "()")
	if cmd.Data != nil {
		return fmt.Sprintf("TPMEventLogAdd(%s, Type: %s, Data: 0x%X)", extendData, cmd.Type, cmd.Data)
	}
	return fmt.Sprintf("TPMEventLogAdd(%s, Type: %s)", extendData, cmd.Type)
}

// String implements fmt.Stringer.
func (cmd *CommandEventLogAdd) String() string {
	return cmd.LogString()
}

// apply implements Command.
func (cmd *CommandEventLogAdd) apply(_ context.Context, tpm *TPM) error {
	tpm.EventLog.Add(cmd.CommandExtend, cmd.Type, cmd.Data)
	return nil
}
