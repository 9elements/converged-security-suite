package main

import (
	"github.com/9elements/converged-security-suite/v2/pkg/log"
	"github.com/alecthomas/kong"
	"github.com/facebookincubator/go-belt/tool/logger"
	"github.com/facebookincubator/go-belt/tool/logger/implementation/dummy"
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
	fianoLog.DefaultLogger = log.NewFianoLogger(dummy.New(), logger.LevelPanic)

	// Run commands
	err := ctx.Run(&context{
		debug: cli.Debug})
	ctx.FatalIfErrorf(err)
}
