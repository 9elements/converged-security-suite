package test

import (
	"bufio"
	"fmt"
	"os"

	a "github.com/logrusorgru/aurora"
)

type TestResult int
type TestStatus int
type TXTSpec int

const (
	ResultNotRun TestResult = iota
	ResultDependencyFailed
	ResultFail
	ResultPass
)

const (
	TestImplemented TestStatus = iota
	TestNotImplemented
	TestPartlyImplemented
)
const (
	TXT TXTSpec = iota
	CBnT
	Common
)

func (t TXTSpec) String() string {
	return [...]string{"TXT", "CBnT", "Common"}[t]
}
func (t TestStatus) String() string {
	return [...]string{"Implemented", "Not implemented", "Partly implemented"}[t]
}
func (t TestResult) String() string {
	return [...]string{"TESTNOTRUN", "DEPENDENCY_FAILED", "FAIL", "PASS"}[t]
}

type Test struct {
	Name         string
	Required     bool
	function     func() (bool, error, error)
	Result       TestResult
	dependencies []*Test
	ErrorText    string
	Status       TestStatus
	Spec         TXTSpec
}

func (self *Test) Run() bool {
	f := bufio.NewWriter(os.Stdout)
	var DepsPassed = true
	// Make sure all dependencies have run and passed
	for idx, _ := range self.dependencies {
		if self.dependencies[idx].Status == TestNotImplemented {
			continue
		}
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
		var err error
		// Now run the test itself
		rc, err1, err2 := self.function()
		if err1 != nil && err2 == nil {
			err = err1
		} else if err1 == nil && err2 != nil {
			err = err2
		}
		if err1 != nil {
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
