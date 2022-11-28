package tpm

import (
	"fmt"
)

type CommandEventLogAdd struct {
	CommandExtend
	Data []byte
}

var _ Command = (*CommandEventLogAdd)(nil)

func NewCommandEventLogAdd(
	cmdExtend CommandExtend,
	data []byte,
) CommandEventLogAdd {
	return CommandEventLogAdd{
		CommandExtend: cmdExtend,
		Data:          data,
	}
}

func (cmd CommandEventLogAdd) LogString() string {
	return fmt.Sprintf("TPMEventLogAdd(Extend: %#+v, Data: 0x%X)", cmd.CommandExtend, cmd.Data)
}

func (cmd CommandEventLogAdd) GoString() string {
	return cmd.LogString()
}

func (cmd CommandEventLogAdd) apply(tpm *TPM) error {
	tpm.EventLog.Add(cmd.CommandExtend, cmd.Data)
	return nil
}
