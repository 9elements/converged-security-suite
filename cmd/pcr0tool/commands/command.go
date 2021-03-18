package commands

import (
	"flag"
)

// Command is an interface of implementations of command verbs
// (like "diff", "sum" etc of "pcr0tool diff"/"pcr0tool sum")
type Command interface {
	// Description explains what this verb commands to do
	Description() string

	// Usage prints the syntax of arguments for this command
	Usage() string

	// SetupFlagSet is called to allow the command implementation
	// to setup which option flags it has.
	SetupFlagSet(flagSet *flag.FlagSet)

	// Execute is the main function here. It is responsible to
	// start the execution of the command.
	//
	// `args` are the arguments left unused by verb itself and options.
	Execute(args []string)
}
