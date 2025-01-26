package main

import (
	"github.com/9elements/converged-security-suite/v2/pkg/log"
	"github.com/alecthomas/kong"
	fianoLog "github.com/linuxboot/fiano/pkg/log"
)

const (
	programName = "amd-suite"
	programDesc = "AMD PSB, SME, SEV and SEV-SNP Test Suite"
)

var (
	gitcommit string
	gittag    string
	testnos   []int
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

	fianoLog.DefaultLogger = log.FianoLogger{}
	err := ctx.Run(&context{})
	ctx.FatalIfErrorf(err)
}
