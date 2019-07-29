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
	fmt.Println("Help!")
	fmt.Println("-t=1,...,51 : Pick test numbers to run specific tests. Numbers will be ordered!")
	fmt.Println("-i : Errors will not stop testing")
	fmt.Println("-h : Shows this help")
	fmt.Println("-l : Lists all Tests with its Test number")
	fmt.Println("-v : Shows Version, License and Copywrite")
}

func listTests() {
	for count, item := range test.TestsCPU {
		fmt.Printf("Test No: %v, %v\n", count+1, item.Name)
	}
	for count, item := range test.TestsTPM {
		fmt.Printf("Test No: %v, %v\n", count+len(test.TestsCPU)+1, item.Name)
	}
	for count, item := range test.TestsFIT {
		fmt.Printf("Test No: %v, %v\n", count+len(test.TestsCPU)+len(test.TestsTPM)+1, item.Name)
	}
	for count, item := range test.TestsMemory {
		fmt.Printf("Test No: %v, %v\n", count+len(test.TestsCPU)+len(test.TestsTPM)+len(test.TestsFIT)+1, item.Name)
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
