package test

import (
	"fmt"

	"github.com/9elements/converged-security-suite/v2/pkg/hwapi"
	"github.com/9elements/converged-security-suite/v2/pkg/tools"
)

const (
	//IntelFITSpecificationTitle the title of Intel FIT BIOS Specification
	IntelFITSpecificationTitle = "Firmware Interface Table BIOS Specification"
	//IntelFITSpecificationDocumentID the document ID of Intel FIT BIOS Specification
	IntelFITSpecificationDocumentID = "599500 Revision 1.2"

	//IntelTXTBGSBIOSSpecificationTitle the title of Intel TXT&BG Server BIOS Specification
	IntelTXTBGSBIOSSpecificationTitle = "Intel Trusted Execution Technology and Boot Guard Server BIOS Specification"
	//IntelTXTBGSBIOSSpecificationDocumentID the document ID of Intel TXT&BG Server BIOS Specification
	IntelTXTBGSBIOSSpecificationDocumentID = "558294 Revision 2.0"

	//IntelTXTSpecificationTitle the title of Intel TXT Specification
	IntelTXTSpecificationTitle = "Intel Trusted Execution Technology (Intel TXT)"
	//IntelTXTSpecificationDocumentID the document ID of Intel TXT Specification
	IntelTXTSpecificationDocumentID = "315168-016"

	//ServerGrantleyPlatformSpecificationTitle is the title of the ACM_Errors.xls
	ServerGrantleyPlatformSpecificationTitle = "TXT error description file for Server Grantley Platform"
	//ServerGrantleyPlatformDocumentID is an empty string
	ServerGrantleyPlatformDocumentID = ""

	//CBtGTXTPlatformSpecificationTitle is the title of the ACM_Errors.xls
	CBtGTXTPlatformSpecificationTitle = "TXT error description file for Converged BtG / TXT  platform"
	//CBtGTXTPlatformDocumentID is an empty string
	CBtGTXTPlatformDocumentID = ""

	//ACPISpecificationTitle is the title of the ACPI spec
	ACPISpecificationTitle = "Advanced Configuration and PowerInterface (ACPI) Specification 6.3"
	//ACPISpecificationDocumentID s an empty string
	ACPISpecificationDocumentID = ""
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
	function      func(hwapi.APIInterfaces, *tools.Configuration) (bool, error, error)
	Result        Result
	dependencies  []*Test
	ErrorText     string
	ErrorTextSpec string
	Status        Status
	Spec          TXTSpec
	// The chapter inside the spec used for this test
	SpecificationChapter string
	// The specification used in this test
	SpecificiationTitle     string
	SpecificationDocumentID string
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
	&testtpmnvramislocked,
	&testauxindexconfig,
}

// TestsLegacy - Summarizes all test for TXT (not CBnT) platforms
var TestsLegacy = []*Test{
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

	// Memory tests
	&testtxtmemoryrangevalid,
	&testmemoryisreserved,
	&testtxtmemoryisdpr,
	&testtxtdprislocked,
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
	&testtpmispresent,
	&testpsindexconfig,
	&testauxindexconfig,
	&testpsindexissvalid,
	&testpcr00valid,
}

// TestsUEFI - Summarizes all test for TXT UEFI boot
var TestsUEFI = []*Test{
	// ACPI tests
	&testRSDPChecksum,
	&testMCFGPresent,
	&testDMARPresent,
	&testDMARValid,
	&testMADTPresent,
	&testMADTValid,
	&testRSDTPresent,
	&testRSDTValid,
	&testXSDTPresent,
	&testXSDTValid,
	&testRSDTorXSDTValid,
}

// TestsTBoot - Summarizes all test for the tboot hypervisor
var TestsTBoot = []*Test{
	&testactiveiommu,
	&testnosiniterrors,
	&testibbistrusted,
	&testhostbridgeDPRcorrect,
	&testhostbridgeDPRislocked,
}

// Run implements the genereal test function and exposes it.
func (t *Test) Run(TxtAPI hwapi.APIInterfaces, config *tools.Configuration) bool {
	var DepsPassed = true
	// Make sure all dependencies have run and passed
	for idx := range t.dependencies {
		if t.dependencies[idx].Status == NotImplemented {
			continue
		}
		if t.dependencies[idx].Result == ResultNotRun {
			t.dependencies[idx].Run(TxtAPI, config)
		}
		if t.dependencies[idx].Result != ResultPass {
			t.ErrorText = t.dependencies[idx].Name + " failed"
			t.Result = ResultDependencyFailed
			DepsPassed = false
		}
	}

	if DepsPassed {
		// Now run the test itself
		rc, testerror, internalerror := t.function(TxtAPI, config)
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
		} else if rc {
			t.Result = ResultPass
		} else {
			t.Result = ResultFail
		}
	}

	return t.Result == ResultPass
}

//RunTestsSilent Runs the specified tests and returns false on the first error encountered
func RunTestsSilent(TxtAPI hwapi.APIInterfaces, config *tools.Configuration, Tests []*Test) (bool, string, error) {

	intErr := fmt.Errorf("Internal error running test")

	for i := range Tests {
		if !Tests[i].Run(TxtAPI, config) && Tests[i].Required {
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
