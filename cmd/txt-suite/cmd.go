package main

import (
	"flag"
	"fmt"
	"sort"
	"strconv"
	"strings"

	"github.com/9elements/txt-suite/pkg/test"
)

var testno = flag.String("t", "", "Select test number 1 - 50. e.g.: -t=1,2,3,4,...")
var keeprunning = flag.Bool("i", false, "Errors will not stop the testing. Tests will keep going.")
var help = flag.Bool("h", false, "Shows help")
var listtests = flag.Bool("l", false, "Lists all test")
var version = flag.Bool("v", false, "Shows Version, copyright info and license")
var tpmdev = flag.String("tpm", "", "Select TPM-Path. e.g.: -tpm=/dev/tpmX, with X as number of the TPM module")

func flagUsed() bool {
	return testno != nil
}

func stayAlive() bool {
	return *keeprunning
}

func showVersion() {
	fmt.Println("TXT test suite version 1.0")
	fmt.Println("Copyright (c) 2019, 9elements Agency GmbH.")
	fmt.Println("This program is licensed under MIT.")
}

func showHelp() {
	fmt.Println("Intel TXT test suite.")
	fmt.Println("Usage: txt-suite [-l] [-h] [-v] [-i] [-t TESTSPEC]")
	fmt.Println("")
	fmt.Println("\t-t TESTSPEC : Only run a subset of tests. TESTSPEC is a comma-separated list of integers or ranges (n-m).")
	fmt.Println("\t-i : Ignore failing tests. Results are written to test_log.json")
	fmt.Println("\t-h : Shows this help")
	fmt.Println("\t-l : Lists all tests with their test number.")
	fmt.Println("\t-v : Shows version, license and copyright.")
}

func listTests() {
	var tests []*test.Test
	for i, _ := range test.TestsCPU {
		tests = append(tests, test.TestsCPU[i])
	}
	for i, _ := range test.TestsTPM {
		tests = append(tests, test.TestsTPM[i])
	}
	for i, _ := range test.TestsFIT {
		tests = append(tests, test.TestsFIT[i])
	}
	for i, _ := range test.TestsMemory {
		tests = append(tests, test.TestsMemory[i])
	}

	for i, _ := range tests {
		fmt.Printf("Test No: %v, %v\n", i, tests[i].Name)
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
		if strings.Contains(*testno, "-") {
			testrange = strings.Split(*testno, "-")
			testmin, err = strconv.Atoi(testrange[0])
			if err != nil {
				return nil, err
			}
			testmax, err = strconv.Atoi(testrange[1])
			if err != nil {
				return nil, err
			}

			for i := testmin; i < testmax; i++ {
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
