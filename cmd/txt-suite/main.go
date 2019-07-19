package main

import (
	"flag"
	"fmt"
	"os"
	"sort"

	"github.com/9elements/txt-suite/pkg/test"
)

var (
	testnos []int
	testerg bool
)

func run() bool {
	var result = false
	testOffset := 0

	for idx, _ := range test.TestsCPU {
		if sort.SearchInts(testnos, idx) <= len(testnos) {
			continue
		}

		if !test.TestsCPU[idx].Run() && test.TestsCPU[idx].Required {
			result = true
		}
	}

	testOffset += len(test.TestsCPU)

	for idx, _ := range test.TestsTPM {
		if sort.SearchInts(testnos, idx+testOffset) <= len(testnos) {
			continue
		}

		if !test.TestsTPM[idx].Run() && test.TestsTPM[idx].Required {
			result = true
		}
	}

	testOffset += len(test.TestsTPM)

	for idx, _ := range test.TestsFIT {
		if sort.SearchInts(testnos, idx+testOffset) <= len(testnos) {
			continue
		}

		if !test.TestsFIT[idx].Run() && test.TestsFIT[idx].Required {
			result = true
		}
	}

	testOffset += len(test.TestsFIT)

	for idx, _ := range test.TestsMemory {
		if sort.SearchInts(testnos, idx+testOffset) <= len(testnos) {
			continue
		}

		if !test.TestsMemory[idx].Run() && test.TestsMemory[idx].Required {
			result = true
		}
	}
	return result
}

func main() {
	flag.Parse()

	if flagUsed() == true {
		testnos, _ = deconstructFlag()
	}

	if !*help && !*listtests {
		err := test.ConnectTPM("/dev/tpm0")
		if err != nil {
			fmt.Printf("Cannot connect to TPM: %s\n", err)
			return
		}

		err = test.LoadFITFromMemory()
		if err != nil {
			fmt.Printf("Cannot load FIT from memory: %s\n", err)
			return
		}

		run()
	} else {
		if *listtests == true {
			listTests()
		}
		if *help == true {
			showHelp()
		}
	}

	ret := run()
	if ret {
		os.Exit(1)
	} else {
		os.Exit(0)
	}
}
