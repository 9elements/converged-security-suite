package printnodes

import (
	"flag"
	"fmt"
	"log"
	"os"
	"strings"

	fianoGUID "github.com/linuxboot/fiano/pkg/guid"
	fianoUEFI "github.com/linuxboot/fiano/pkg/uefi"

	pkgbytes "github.com/9elements/converged-security-suite/v2/pkg/bytes"
	"github.com/9elements/converged-security-suite/v2/pkg/uefi"
	"github.com/9elements/converged-security-suite/v2/pkg/uefi/ffs"
)

func assertNoError(err error) {
	if err != nil {
		log.Fatal(err)
	}
}

func usageAndExit() {
	flag.Usage()
	os.Exit(2)
}

// Command is the implementation of `commands.Command`.
type Command struct {
	asTree *bool
}

// Usage prints the syntax of arguments for this command
func (cmd Command) Usage() string {
	return "<firmware>"
}

// Description explains what this verb commands to do
func (cmd Command) Description() string {
	return "dump UEFI tree nodes"
}

// SetupFlagSet is called to allow the command implementation
// to setup which option flags it has.
func (cmd *Command) SetupFlagSet(flag *flag.FlagSet) {
	cmd.asTree = flag.Bool("as-tree", false, `display the result as a tree`)
}

type visitor struct {
	Callback func(*visitor, fianoUEFI.Firmware) error
	Parent   *visitor
}

func (v *visitor) Run(f fianoUEFI.Firmware) error {
	return f.Apply(v)
}

func (v *visitor) Visit(f fianoUEFI.Firmware) error {
	err := v.Callback(v, f)
	if err != nil {
		return err
	}

	vCopy := *v
	vCopy.Parent = v
	return f.ApplyChildren(&vCopy)
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

	firmware, err := uefi.ParseUEFIFirmwareFile(imagePath)
	assertNoError(err)

	nodes, err := firmware.GetByRange(pkgbytes.Range{
		Offset: 0,
		Length: uint64(len(firmware.Buf())),
	})
	assertNoError(err)

	rangeMap := map[fianoUEFI.Firmware]pkgbytes.Range{}
	for _, node := range nodes {
		rangeMap[node.Firmware] = node.Range
	}

	err = firmware.Apply(&visitor{Callback: func(v *visitor, f fianoUEFI.Firmware) error {
		// calculating the nesting level
		nestingLevel := 0
		{
			parent := v.Parent
			for parent != nil {
				nestingLevel++
				parent = parent.Parent
			}
		}

		var guid *fianoGUID.GUID
		switch f := f.(type) {
		case *fianoUEFI.File:
			guid = &f.Header.GUID
		case *fianoUEFI.FirmwareVolume:
			guid = &f.FVName
		}
		var guidString string
		if guid != nil {
			guidString = guid.String()
		} else {
			guidString = `________-____-____-____-____________`
		}

		var moduleName string
		{
			moduleNamePtr := ffs.Node{Firmware: f}.ModuleName()
			if moduleNamePtr != nil {
				moduleName = *moduleNamePtr
			}
		}

		nodeRange := rangeMap[f]
		if *cmd.asTree {
			fmt.Print(strings.Repeat("  ", nestingLevel))
		} else {
			fmt.Printf("%d ", nestingLevel)
		}
		fmt.Printf("%s %T %s %d %d\n", guidString, f, moduleName, nodeRange.Offset,
			nodeRange.Length)

		return nil
	}})
	assertNoError(err)
}
