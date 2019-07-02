package main

import (
	"github.com/9elements/txt-suite/pkg/test"
)

func main() {
	// tests 1-15
	test.RunCPUTests()
	// tests 16-20
	test.RunTPMTests()
}
