package test

import "github.com/9elements/txt-suite/pkg/hwapi"

// Result exposes the type for test results
type Result int

const (
	// ResultNotRun indicates that a test was skipped
	ResultNotRun Result = iota

	// ResultDependencyFailed indicates that the previous dependency test failed
	ResultDependencyFailed

	// ResultInternalError indicates that a library function failed at some point in the test
	ResultInternalError

	// ResultFail indicates that the test failed
	ResultFail

	// ResultWarn indicates that the test failed for the standard configuration but can still be valid in a different configuration of TXT
	ResultWarn

	// ResultPass indicates that the test succeeded.
	ResultPass
)

func (t Result) String() string {
	return [...]string{"TESTNOTRUN", "DEPENDENCY_FAILED", "INTERNAL_ERROR", "FAIL", "WARN", "PASS"}[t]
}

// Status exposes the type for test status
type Status int

const (
	// Implemented indicates that a test is implemented completly
	Implemented Status = iota

	// NotImplemented indicates that test is NOT implemented
	NotImplemented

	// PartlyImplemented indicates that a test implements a certain aspect
	PartlyImplemented
)

func (t Status) String() string {
	return [...]string{"Implemented", "Not implemented", "Partly implemented"}[t]
}

// TXTSpec exposes the type to differentiate between TXT specs
type TXTSpec int

const (
	// TXT indicates
	TXT TXTSpec = iota

	// CBnT indicates
	CBnT

	// Common indicates
	Common
)

func (t TXTSpec) String() string {
	return [...]string{"TXT", "CBnT", "Common"}[t]
}

// Test exposes the structure in which information about TXT tests are held
type Test struct {
	Name     string
	Required bool
	//testerror: If test fails and returns an testerror -> test failure
	//internalerror: If test fails and returns an internalerror
	//-> mostly api errors, but not directly testrelated problem.
	//The return call in test functions shall return only one of the errors,
	//while the other is nil.
	function     func(hwapi.ApiInterfaces) (bool, error, error)
	Result       Result
	dependencies []*Test
	ErrorText    string
	Status       Status
	Spec         TXTSpec
	NonCritical  bool
}

// Run implements the genereal test function and exposes it.
func (t *Test) Run(TxtApi hwapi.ApiInterfaces) bool {
	var DepsPassed = true
	// Make sure all dependencies have run and passed
	for idx := range t.dependencies {
		if t.dependencies[idx].Status == NotImplemented {
			continue
		}
		if t.dependencies[idx].Result == ResultNotRun {
			t.dependencies[idx].Run(TxtApi)
		}
		if t.dependencies[idx].Result != ResultPass {
			t.ErrorText = t.dependencies[idx].Name + " failed"
			t.Result = ResultDependencyFailed
			DepsPassed = false
		}
	}

	if DepsPassed {
		// Now run the test itself
		rc, testerror, internalerror := t.function(TxtApi)
		if internalerror != nil && testerror == nil {
			t.Result = ResultInternalError
			t.ErrorText = internalerror.Error()
		} else if testerror != nil && internalerror == nil {
			t.ErrorText = testerror.Error()
			if t.NonCritical {
				t.Result = ResultWarn
			} else {
				t.Result = ResultFail
			}
		} else if rc {
			t.Result = ResultPass
		} else {
			t.Result = ResultFail
		}
	}

	return t.Result == ResultPass
}
