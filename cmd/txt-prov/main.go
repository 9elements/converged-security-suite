package main

import (
	"github.com/9elements/converged-security-suite/v2/pkg/intel/metadata/manifest"
	"github.com/alecthomas/kong"
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
	manifest.StrictOrderCheck = cli.ManifestStrictOrderCheck

	// Run commands
	err := ctx.Run(&context{
		debug: cli.Debug})
	ctx.FatalIfErrorf(err)
}
