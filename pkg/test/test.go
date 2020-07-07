package test

import (
	"fmt"

	"github.com/9elements/txt-suite/pkg/hwapi"
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

// Define tests for API usage

// TestsTXTReady - Summarizes all test for TXT Ready platforms
var TestsTXTReady = []*Test{
	// CPU tests
	&testcheckforintelcpu,
	&testwaybridgeorlater,
	&testcpusupportstxt,
	&testtxtregisterspaceaccessible,
	&testsupportssmx,
	&testsupportvmx,
	&testia32featurectrl,
	&testtxtnotdisabled,
	&testtxtregisterslocked,
	&testia32debuginterfacelockeddisabled,

	// Memory tests
	&testtxtmemoryrangevalid,
	&testmemoryisreserved,
	&testtxtmemoryisdpr,
	&testtxtdprislocked,
	&testhostbridgeDPRcorrect,
	&testhostbridgeDPRislocked,
	&testsinitintxt,
	&testsinitmatcheschipset,
	&testsinitmatchescpu,
	&testbiosdataregionpresent,
	&testbiosdataregionvalid,
	&testhasmtrr,
	&testhassmrr,
	&testvalidsmrr,
	&testactivesmrr,

	// TPM tests
	&testtpmconnection,
	&testtpm12present,
	&testtpm2present,
	&testtpmispresent,

	&testtpmnvramislocked,
	&testpsindexconfig,
	&testauxindexconfig,
	&testpoindexconfig,
}

// TestsTXTLegacyBoot - Summarizes all test for TXT legacy boot (not CvBG) platforms
var TestsTXTLegacyBoot = []*Test{
	// CPU tests
	&testcheckforintelcpu,
	&testwaybridgeorlater,
	&testcpusupportstxt,
	&testtxtregisterspaceaccessible,
	&testsupportssmx,
	&testsupportvmx,
	&testia32featurectrl,
	&testtxtnotdisabled,
	&testtxtregisterslocked,
	&testia32debuginterfacelockeddisabled,
	&testibbmeasured,
	&testibbistrusted,

	// Memory tests
	&testtxtmemoryrangevalid,
	&testmemoryisreserved,
	&testtxtmemoryisdpr,
	&testtxtdprislocked,
	&testhostbridgeDPRcorrect,
	&testhostbridgeDPRislocked,
	&testsinitintxt,
	&testsinitmatcheschipset,
	&testsinitmatchescpu,
	&testbiosdataregionpresent,
	&testbiosdataregionvalid,
	&testhasmtrr,
	&testhassmrr,
	&testvalidsmrr,
	&testactivesmrr,

	// FIT tests
	&testfitvectorisset,
	&testhasfit,
	&testhasbiosacm,
	&testhasibb,
	&testhaslcpTest,
	&testibbcoversresetvector,
	&testibbcoversfitvector,
	&testibbcoversfit,
	&testnoibboverlap,
	&testnobiosacmoverlap,
	&testnobiosacmisbelow4g,
	&testpolicyallowstxt,
	&testbiosacmvalid,
	&testbiosacmsizecorrect,
	&testbiosacmaligmentcorrect,
	&testbiosacmmatcheschipset,
	&testbiosacmmatchescpu,

	// TPM tests
	&testtpmconnection,
	&testtpm12present,
	&testtpm2present,
	&testtpmispresent,
	&testtpmnvramislocked,
	&testpsindexconfig,
	&testauxindexconfig,
	&testpoindexconfig,
	&testpsindexissvalid,
	&testpoindexissvalid,
	&testpcr00valid,
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

//RunTestsSilent Runs the specified tests and returns false on the first error encountered
func RunTestsSilent(TxtAPI hwapi.ApiInterfaces, Tests []*Test) (bool, string, error) {

	intErr := fmt.Errorf("Internal error running test")

	for i := range Tests {
		if !Tests[i].Run(TxtAPI) && Tests[i].Required {
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
