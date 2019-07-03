package main

import (
	"github.com/9elements/txt-suite/pkg/test"
)

func main() {
	for _, t := range test.TestsCPU {
		t.Run()
	}

	test.ConnectTPM("/dev/tpm0")
	for _, t := range test.TestsTPM {
		t.Run()
	}

	for _, t := range test.TestsFIT {
		t.Run()
	}
}
