package main

import (
	"flag"
	"fmt"
	"sort"
	"strconv"
	"strings"

	"github.com/9elements/converged-security-suite/pkg/test"
)

var testno = flag.String("t", "", "Select test number 1 - 50. e.g.: -t=1,2,3,4,...")
var interactive = flag.Bool("i", false, "Interactive mode. Errors will stop the testing.")
var listtests = flag.Bool("l", false, "Lists all test")
var teststomarkdown = flag.Bool("m", false, "Output test implementation state as Markdown")
var version = flag.Bool("v", false, "Shows Version, copyright info and license")
var tpmdev = flag.String("tpm", "", "Select TPM-Path. e.g.: -tpm=/dev/tpmX, with X as number of the TPM module")
var logpath = flag.String("log", "", "Give a path/filename for test result output in JSON format. e.g.: /path/to/filename.json")
var all = flag.Bool("all", false, "Run all the tests of the suite")
var uefi = flag.Bool("uefi", false, "Test if platform is UEFI boot enabled")
var txtready = flag.Bool("txtready", false, "Run TXTReady specific tests")
var tboot = flag.Bool("tboot", false, "Test if tboot hypervisor runs correctly")
var cbnt = flag.Bool("cbnt", false, "Run CBnT specific tests")
var configFile = flag.String("config", "", "Give a path/filename to configuration file")

func flagUsed() bool {
	return testno != nil
}

func flagInteractive() bool {
	return *interactive
}

func showVersion() {
	fmt.Println("Converged Security Suite - TXT-Suite")
	fmt.Println("")
	fmt.Println("BSD 3-Clause License")
	fmt.Println("")
	fmt.Println("Copyright (c) 2020, 9elements GmbH.")
	fmt.Println("Copyright (c) 2020, facebook Inc.")
	fmt.Println("All rights reserved.")
}

func getTests() []*test.Test {
	var tests []*test.Test
	for i := range test.TestsCPU {
		tests = append(tests, test.TestsCPU[i])
	}
	for i := range test.TestsTPM {
		tests = append(tests, test.TestsTPM[i])
	}
	for i := range test.TestsFIT {
		tests = append(tests, test.TestsFIT[i])
	}
	for i := range test.TestsMemory {
		tests = append(tests, test.TestsMemory[i])
	}
	for i := range test.TestsACPI {
		tests = append(tests, test.TestsACPI[i])
	}
	return tests
}

func listTests() {
	tests := getTests()

	for i := range tests {
		fmt.Printf("Test No: %v, %v\n", i, tests[i].Name)
	}
}

func listTestsAsMarkdown() {
	var teststate string
	tests := getTests()

	fmt.Println("Id | Test | Implemented | Document | Chapter")
	fmt.Println("------------|------------|------------|------------|------------")
	for i := range tests {
		if tests[i].Status == test.Implemented {
			teststate = ":white_check_mark:"
		} else if tests[i].Status == test.NotImplemented {
			teststate = ":x:"
		} else {
			teststate = ":clock1:"
		}
		docID := tests[i].SpecificationDocumentID
		if docID != "" {
			docID = "Document " + docID
		}
		fmt.Printf("%02d | %-48s | %-22s | %-28s | %-56s\n", i, tests[i].Name, teststate, docID, tests[i].SpecificationChapter)
	}
}

func deconstructFlag() ([]int, error) {
	var testnos []int
	var tmpstrings []string
	var testrange []string
	var testmin int
	var testmax int
	var err error
	tmpstrings = strings.Split(*testno, ",")
	for _, item := range tmpstrings {
		if strings.Contains(item, "-") {
			testrange = strings.Split(item, "-")
			testmin, err = strconv.Atoi(testrange[0])
			if err != nil {
				return nil, err
			}
			testmax, err = strconv.Atoi(testrange[1])
			if err != nil {
				return nil, err
			}

			for i := testmin; i <= testmax; i++ {
				testnos = append(testnos, i)
			}

		} else {
			tmpno, err := strconv.Atoi(item)
			if err != nil {
				return nil, err
			}
			testnos = append(testnos, tmpno)
		}
	}
	//Sort array
	sort.Ints(testnos)
	return testnos, nil

}
