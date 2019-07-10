package test

import (
	"bufio"
	"fmt"
	"os"

	a "github.com/logrusorgru/aurora"
)

type Test struct {
	name     string
	required bool
	function func() (bool, error)
}

func (self *Test) Run() bool {
	f := bufio.NewWriter(os.Stdout)

	fmt.Printf("%s: ", self.name)
	f.Flush()

	rc, err := self.function()
	if err != nil {
		fmt.Printf("%s\n%s\n", a.Bold(a.Red("ERROR")), a.Bold(err))
		f.Flush()
		return false
	}

	if rc {
		fmt.Println(a.Green("OK"))
	} else {
		fmt.Println(a.Red("FAIL"))
	}
	f.Flush()

	return rc
}
