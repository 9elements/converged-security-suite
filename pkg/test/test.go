package test

import (
	"bufio"
	"fmt"
	"os"
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
		fmt.Printf("ERROR\n\t%s\n", err)
		f.Flush()
		return false
	}

	if rc {
		fmt.Println("OK")
	} else {
		fmt.Println("FAIL\n\t%s", "TODO")
	}
	f.Flush()

	return rc
}
