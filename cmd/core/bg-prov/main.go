package main

import (
	"github.com/alecthomas/kong"
	"github.com/linuxboot/fiano/pkg/intel/metadata/cbnt"
	fianoLog "github.com/linuxboot/fiano/pkg/log"
	log "github.com/sirupsen/logrus"
)

const (
	programName = "bg-prov"
	programDesc = "Intel BtG/CBnT provisioning tooling"
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
	cbnt.StrictOrderCheck = cli.ManifestStrictOrderCheck

	if cli.Debug {
		log.SetLevel(log.DebugLevel)
	}

	fianologger := log.StandardLogger()

	fianoLog.DefaultLogger = fianologger
	err := ctx.Run(&context{Debug: cli.Debug})
	ctx.FatalIfErrorf(err)
}
