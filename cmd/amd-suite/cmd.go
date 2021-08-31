package main

import (
	"github.com/9elements/converged-security-suite/v2/pkg/amd/psb"
)

// Context for kong command line parser
type context struct {
	debug bool
}

type showKeyDBCmd struct {
	FwPath string `arg required name:"fwpath" help:"Path to UEFI firmware image." type:"path"`
}

var cli struct {
	Debug     bool         `help:"Enable debug mode"`
	ShowKeyDB showKeyDBCmd `cmd help:"Shows content of Key Database"`
}

func (s *showKeyDBCmd) Run(ctx *context) error {
	psb.ShowKeyDB()
	return nil
}
