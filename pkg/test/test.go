package test

import (
	"bufio"
	"fmt"
	"os"

	a "github.com/logrusorgru/aurora"
)

type TestResult int

const (
	ResultNotRun TestResult = iota
	ResultDependencyFailed
	ResultFail
	ResultPass
)

func (t TestResult) String() string {
        return [...]string{"TESTNOTRUN", "DEPENDENCY_FAILED", "FAIL", "PASS"}[t]
}

type Test struct {
	Name         string
	Required     bool
	function     func() (bool, error)
	Result       TestResult
	dependencies []*Test
	ErrorText    string
}

func (self *Test) Run() bool {
	f := bufio.NewWriter(os.Stdout)
	var DepsPassed = true
	// Make sure all dependencies have run and passed
	for idx, _ := range self.dependencies {
		if self.dependencies[idx].Result == ResultNotRun {
			self.dependencies[idx].Run()
		}
		if self.dependencies[idx].Result != ResultPass {
			self.ErrorText = self.dependencies[idx].Name + " failed"
			self.Result = ResultDependencyFailed
			DepsPassed = false
		}
	}

	fmt.Printf("%s: ", self.Name)
	f.Flush()
	if DepsPassed {
		// Now run the test itself
		rc, err := self.function()
		if err != nil {
			self.ErrorText = err.Error()
			self.Result = ResultFail
		} else if rc {
			self.Result = ResultPass
		} else {
			self.Result = ResultFail
		}
	}

	if self.Result == ResultPass {
		fmt.Println(a.Green(self.Result))
	} else {
		fmt.Println(a.Red(self.Result))
	}
	if self.ErrorText != "" {
		fmt.Println(a.Bold(self.ErrorText))
	}
	f.Flush()

	return self.Result == ResultPass
}
