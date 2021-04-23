package main

import (
	"github.com/alecthomas/kong"
)

const (
	programName = "bg-prov"
	programDesc = "Intel BootGuard provisioning tooling"
)

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
	err := ctx.Run(&context{})
	ctx.FatalIfErrorf(err)
}
