package test

import (
	"fmt"

	"github.com/9elements/go-linux-lowlevel-hw/pkg/hwapi"
)

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

	// ResultPass indicates that the test succeeded.
	ResultPass
)

func (t Result) String() string {
	return [...]string{"TESTNOTRUN", "DEPENDENCY_FAILED", "INTERNAL_ERROR", "FAIL", "PASS"}[t]
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

// Test exposes the structure in which information about TXT tests are held
type Test struct {
	Name     string
	Required bool
	//testerror: If test fails and returns an testerror -> test failure
	//internalerror: If test fails and returns an internalerror
	//-> mostly api errors, but not directly testrelated problem.
	//The return call in test functions shall return only one of the errors,
	//while the other is nil.
	function      func(hwapi.LowLevelHardwareInterfaces, *PreSet) (bool, error, error)
	Result        Result
	dependencies  []*Test
	ErrorText     string
	ErrorTextSpec string
	Status        Status
	// The chapter inside the spec used for this test
	SpecificationChapter string
	// The specification used in this test
	SpecificiationTitle     string
	SpecificationDocumentID string
}

// Run implements the genereal test function and exposes it.
func (t *Test) Run(hw hwapi.LowLevelHardwareInterfaces, preset *PreSet) bool {
	var DepsPassed = true
	// Make sure all dependencies have run and passed
	for idx := range t.dependencies {
		if t.dependencies[idx].Status == NotImplemented {
			continue
		}
		if t.dependencies[idx].Result == ResultNotRun {
			t.dependencies[idx].Run(hw, preset)
		}
		if t.dependencies[idx].Result != ResultPass {
			t.ErrorText = t.dependencies[idx].Name + " failed"
			t.Result = ResultDependencyFailed
			DepsPassed = false
		}
	}

	if DepsPassed {
		// Now run the test itself
		rc, testerror, internalerror := t.function(hw, preset)
		if internalerror != nil && testerror == nil {
			t.Result = ResultInternalError
			t.ErrorText = internalerror.Error()
		} else if testerror != nil && internalerror == nil {
			t.ErrorText = testerror.Error()
			if t.SpecificiationTitle != "" || t.SpecificationDocumentID != "" {
				t.ErrorTextSpec = "Please have a look at "
				if t.SpecificiationTitle != "" {
					t.ErrorTextSpec += t.SpecificiationTitle + " "
				}
				if t.SpecificationDocumentID != "" {
					t.ErrorTextSpec += "document ID '" + t.SpecificationDocumentID + "' "
				}
				if t.SpecificationChapter != "" {
					t.ErrorTextSpec += "chapter '" + t.SpecificationChapter + "' "
				}
				t.ErrorTextSpec += "for implementation details."
			}
			t.Result = ResultFail
		} else if testerror != nil && internalerror != nil {
			t.ErrorText = fmt.Sprintf("\n %v:\n %+v\n", testerror.Error(), internalerror)
			if t.SpecificiationTitle != "" || t.SpecificationDocumentID != "" {
				t.ErrorTextSpec = "Please have a look at "
				if t.SpecificiationTitle != "" {
					t.ErrorTextSpec += t.SpecificiationTitle + " "
				}
				if t.SpecificationDocumentID != "" {
					t.ErrorTextSpec += "document ID '" + t.SpecificationDocumentID + "' "
				}
				if t.SpecificationChapter != "" {
					t.ErrorTextSpec += "chapter '" + t.SpecificationChapter + "' "
				}
				t.ErrorTextSpec += "for implementation details."
			}
			t.Result = ResultFail
		} else if rc {
			t.Result = ResultPass
		} else {
			t.Result = ResultFail
		}
	}

	return t.Result == ResultPass
}

// RunTestsSilent Runs the specified tests and returns false on the first error encountered
func RunTestsSilent(hw hwapi.LowLevelHardwareInterfaces, preset *PreSet, Tests []*Test) (bool, string, error) {

	intErr := fmt.Errorf("internal error running test")

	for i := range Tests {
		if !Tests[i].Run(hw, preset) && Tests[i].Required {
			if Tests[i].Status == NotImplemented {
				continue
			}
			if Tests[i].Result == ResultInternalError {
				return false, "", intErr
			}
			return false, "Test " + Tests[i].Name + " returned " + Tests[i].Result.String() + ": " + Tests[i].ErrorText, nil
		}
	}
	return true, "", nil
}
