package main

import (
	"fmt"

	"github.com/9elements/txt-suite/pkg/test"
)

func run() {
	for _, t := range test.TestsCPU {
		t.Run()
	}

	for _, t := range test.TestsTPM {
		t.Run()
	}

	for _, t := range test.TestsFIT {
		t.Run()
	}

	for _, t := range test.TestsMemory {
		t.Run()
	}
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

	run()
}
