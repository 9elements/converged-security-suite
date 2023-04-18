package main

import (
	"github.com/9elements/converged-security-suite/v2/pkg/log"
	"github.com/alecthomas/kong"
	"github.com/linuxboot/fiano/pkg/intel/metadata/cbnt"
	fianoLog "github.com/linuxboot/fiano/pkg/log"
)

const (
	programName = "txt-suite"
	programDesc = "Intel TXT Test Suite"
)

var (
	testnos   []int
	testerg   bool
	logfile   = "test_log.json"
	gitcommit string
	gittag    string
)

type temptest struct {
	Testnumber int
	Testname   string
	Result     string
	Error      string
	Status     string
}

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
	err := ctx.Run(&context{})
	ctx.FatalIfErrorf(err)
}
