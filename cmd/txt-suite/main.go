package main

import (
	"fmt"
	"os"

	"github.com/9elements/txt-suite/pkg/test"
)

func run() bool {
	var result = false
	for idx, _ := range test.TestsCPU {
		if !test.TestsCPU[idx].Run() && test.TestsCPU[idx].Required {
			result = true
		}
	}

	for idx, _ := range test.TestsTPM {
		if !test.TestsTPM[idx].Run() && test.TestsTPM[idx].Required {
			result = true
		}
	}

	for idx, _ := range test.TestsFIT {
		if !test.TestsFIT[idx].Run() && test.TestsFIT[idx].Required {
			result = true
		}
	}

	for idx, _ := range test.TestsMemory {
		if !test.TestsMemory[idx].Run() && test.TestsMemory[idx].Required {
			result = true
		}
	}
	return result
}

func main() {
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

	ret := run()
	if (ret) {
		os.Exit(1)
	} else {
		os.Exit(0)
	}
}
