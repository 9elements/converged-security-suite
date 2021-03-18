package dumpregisters

import (
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"runtime"

	"github.com/9elements/converged-security-suite/v2/pkg/hwapi"
	"github.com/9elements/converged-security-suite/v2/pkg/registers"
)

func assertNoError(err error) {
	if err != nil {
		panic(err)
	}
}

// Command is the implementation of `commands.Command`.
type Command struct {
	outputFile *string
}

// Usage prints the syntax of arguments for this command
func (cmd Command) Usage() string {
	return ""
}

// Description explains what this verb commands to do
func (cmd Command) Description() string {
	return "dump status registers from /dev/mem and /dev/cpu/0/msr. Works only on Linux"
}

// SetupFlagSet is called to allow the command implementation
// to setup which option flags it has.
func (cmd *Command) SetupFlagSet(flag *flag.FlagSet) {
	cmd.outputFile = flag.String("output", "",
		"[optional] dumps all registers into a file")
}

// Execute is the main function here. It is responsible to
// start the execution of the command.
//
// `args` are the arguments left unused by verb itself and options.
func (cmd Command) Execute(args []string) {
	if runtime.GOOS != "linux" {
		panic("command is supported only on Linux platform")
	}

	txtAPI := hwapi.GetAPI()

	txtConfig, err := registers.FetchTXTConfigSpace(txtAPI)
	assertNoError(err)
	txtRegisters, err := registers.ReadTXTRegisters(txtConfig)
	if err != nil {
		fmt.Printf("[WARNING]: Reading TXT registers returned an error: %v\n", err)
	}

	msrRegisters, err := txtAPI.GetMSRRegisters()
	if err != nil {
		fmt.Printf("[WARNING]: Reading MSR registers returned an error: %v\n", err)
	}

	allRegisters := append(txtRegisters, msrRegisters...)
	for _, reg := range allRegisters {
		fmt.Printf("\n")
		printRegister(reg)
	}

	if len(*cmd.outputFile) > 0 {
		b, err := json.Marshal(allRegisters)
		if err != nil {
			panic(fmt.Sprintf("failed to marshal registers into json, err: %v", err))
		}
		err = ioutil.WriteFile(*cmd.outputFile, b, 0666)
		if err != nil {
			panic(fmt.Sprintf("failed to write data to file %s, err: %v", *cmd.outputFile, err))
		}
	}
}

func printRegister(reg registers.Register) {
	fmt.Printf("Register: %s\n", reg.ID())
	switch r := reg.(type) {
	case registers.RawRegister:
		for idx, b := range r.Raw() {
			if idx%8 == 0 {
				fmt.Printf("\n")
			}
			fmt.Printf("%X ", b)
		}
		fmt.Printf("\n")
	case registers.RawRegister8:
		fmt.Println("          1         0")
		fmt.Println("         109876543210")
		fmt.Printf("%08X %08b\n", r.Raw(), r.Raw())
	case registers.RawRegister16:
		fmt.Println("          2         1         0")
		fmt.Println("         1098765432109876543210")
		fmt.Printf("%08X %016b\n", r.Raw(), r.Raw())
	case registers.RawRegister32:
		fmt.Println("          3         2         1         0")
		fmt.Println("         10987654321098765432109876543210")
		fmt.Printf("%08X %032b\n", r.Raw(), r.Raw())
	case registers.RawRegister64:
		fmt.Println("                    6         5         4         3         2         1         0")
		fmt.Println("                 3210987654321098765432109876543210987654321098765432109876543210")
		fmt.Printf("%016X %064b\n", r.Raw(), r.Raw())
	default:
		panic(fmt.Sprintf("register %s doesn't support any of raw access interfaces", r.ID()))
	}

	var fieldsTotalSize uint8
	for _, field := range reg.Fields() {
		if len(field.Value) == 8 {
			fmt.Printf("\t%2d-%2d: %8X: %s\n", fieldsTotalSize, fieldsTotalSize+field.BitSize-1,
				registers.FieldValueToNumber(field.Value), field.Name)
		} else {
			fmt.Printf("\t%2d-%2d: %8X: %s\n", fieldsTotalSize, fieldsTotalSize+field.BitSize-1, field.Value, field.Name)
		}
		fieldsTotalSize += field.BitSize
	}
}
