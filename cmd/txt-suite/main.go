package main

import (
	"fmt"

	"github.com/9elements/txt-suite/pkg/test"
)

func run() {
	for _, t := range test.TestsCPU {
		if !t.Run() {
			return
		}
	}

	for _, t := range test.TestsTPM {
		if !t.Run() {
			return
		}
	}

	for _, t := range test.TestsFIT {
		if !t.Run() {
			return
		}
	}

	for _, t := range test.TestsMemory {
		if !t.Run() {
			return
		}
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
