package test

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
	IntelTXTSpecificationDocumentID = "315168-017"

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
var TestsTXTLegacy = []*Test{
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
var TestsTXTUEFI = []*Test{
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
var TestsTXTTBoot = []*Test{
	&testactiveiommu,
	&testnosiniterrors,
	&testibbistrusted,
	&testhostbridgeDPRcorrect,
	&testhostbridgeDPRislocked,
}
