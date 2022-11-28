package tpm

import (
	"context"
	"fmt"
	"strings"
)

type CommandEventLogAdd struct {
	CommandExtend
	Data []byte
}

var _ Command = (*CommandEventLogAdd)(nil)

func NewCommandEventLogAdd(
	cmdExtend CommandExtend,
	data []byte,
) *CommandEventLogAdd {
	return &CommandEventLogAdd{
		CommandExtend: cmdExtend,
		Data:          data,
	}
}

func (cmd *CommandEventLogAdd) LogString() string {
	extendData := strings.Trim(strings.ReplaceAll(cmd.CommandExtend.String(), "TPMExtend", ""), "()")
	if cmd.Data != nil {
		return fmt.Sprintf("TPMEventLogAdd(%v, Data: 0x%X)", extendData, cmd.Data)
	}
	return fmt.Sprintf("TPMEventLogAdd(%s)", extendData)
}

func (cmd *CommandEventLogAdd) String() string {
	return cmd.LogString()
}

func (cmd *CommandEventLogAdd) apply(_ context.Context, tpm *TPM) error {
	tpm.EventLog.Add(cmd.CommandExtend, cmd.Data)
	return nil
}
