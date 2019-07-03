package test

import (
	"fmt"
)

type Test struct {
	name     string
	required bool
	function func() (bool, error)
}

func (self *Test) Run() bool {
	fmt.Printf("%s: ", self.name)
	rc, err := self.function()
	if err != nil {
		fmt.Printf("ERROR\n\t%s\n", err)
		return false
	}
	if rc {
		fmt.Println("OK")
	} else {
		fmt.Println("FAIL\n\t%s", "TODO")
	}

	return rc
}
