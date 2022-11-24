package displayfwinfo

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io/ioutil"
	"os"

	fianoUEFI "github.com/linuxboot/fiano/pkg/uefi"

	"github.com/9elements/converged-security-suite/v2/pkg/dmidecode"
)

func usageAndExit() {
	flag.Usage()
	os.Exit(2)
}

// Command is the implementation of `commands.Command`.
type Command struct{}

// Usage prints the syntax of arguments for this command
func (cmd Command) Usage() string {
	return "<path to the image>"
}

// Description explains what this verb commands to do
func (cmd Command) Description() string {
	return "display information about firmware image"
}

// SetupFlagSet is called to allow the command implementation
// to setup which option flags it has.
func (cmd *Command) SetupFlagSet(flag *flag.FlagSet) {
}

// Execute is the main function here. It is responsible to
// start the execution of the command.
//
// `args` are the arguments left unused by verb itself and options.
func (cmd Command) Execute(args []string) {
	if len(args) < 1 {
		_, _ = fmt.Fprintf(flag.CommandLine.Output(), "error: no path to the firmare was specified\n")
		usageAndExit()
	}
	if len(args) > 1 {
		_, _ = fmt.Fprintf(flag.CommandLine.Output(), "error: too many parameters\n")
		usageAndExit()
	}
	imagePath := args[0]

	imageBytes, err := ioutil.ReadFile(imagePath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "unable to read image '%s': %v\n", imagePath, err)
		return
	}

	dmiTable, err := dmidecode.DMITableFromFirmware(imageBytes)
	if errors.As(err, &dmidecode.ErrFindSMBIOSInFirmware{}) {
		fianoUEFI.DisableDecompression = false
		dmiTable, err = dmidecode.DMITableFromFirmware(imageBytes)
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "unable to parse the image info: '%v'\n", err)
		return
	}

	b, err := json.Marshal(dmiTable.BIOSInfo())
	if err != nil {
		fmt.Fprintf(os.Stderr, "unable to serialize BIOSInfo: %v\n", err)
		return
	}
	fmt.Printf("%s\n", b)
}
