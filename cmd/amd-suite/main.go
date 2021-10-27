package main

import (
	"github.com/9elements/converged-security-suite/v2/pkg/log"
	"github.com/alecthomas/kong"
	fianoLog "github.com/linuxboot/fiano/pkg/log"
)

const programName = "amd-suite"
const programDesc = "AMD PSP and PSB management tool"

var (
	gitcommit string
	gittag    string
)

func main() {
	ctx := kong.Parse(&cli,
		kong.Name(programName),
		kong.Description(programDesc),
		kong.UsageOnError(),
		kong.ConfigureHelp(kong.HelpOptions{
			Compact: true,
			Summary: true,
		}))
	fianoLog.DefaultLogger = log.DummyLogger{}

	// Run commands
	err := ctx.Run(&context{
		debug: cli.Debug})
	ctx.FatalIfErrorf(err)
}
