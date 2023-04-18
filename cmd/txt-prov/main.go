package main

import (
	"github.com/9elements/converged-security-suite/v2/pkg/log"
	"github.com/alecthomas/kong"
	"github.com/linuxboot/fiano/pkg/intel/metadata/cbnt"
	fianoLog "github.com/linuxboot/fiano/pkg/log"
)

const programName = "txt-prov"
const programDesc = "Intel TXT provisioning tool"

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
	cbnt.StrictOrderCheck = cli.ManifestStrictOrderCheck
	fianoLog.DefaultLogger = log.FianoLogger{}

	// Run commands
	err := ctx.Run(&context{
		debug: cli.Debug})
	ctx.FatalIfErrorf(err)
}
