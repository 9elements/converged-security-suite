package main

import (
	"flag"
	"os"
	"sort"

	"github.com/9elements/txt-suite/pkg/test"
)

var (
	testnos []int
	testerg bool
)

func getTests() []*test.Test {
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
	return tests
}

func run() bool {
	var result = false
	var tests []*test.Test

	tests = getTests()

	for idx, _ := range tests {
		if len(testnos) > 0 {
			// SearchInt returns an index where to "insert" idx
			i := sort.SearchInts(testnos, idx)
			if i >= len(testnos) {
				continue
			}
			// still here? i must be within testnos.
			if testnos[i] != idx {
				continue
			}
		}

		if !tests[idx].Run() && tests[idx].Required && !stayAlive() {
			result = true
			break
		}
	}

	return result
}

func main() {
	ret := false

	flag.Parse()

	if flagUsed() == true {
		testnos, _ = deconstructFlag()
	}

	if *tpmdev != "" {
		test.TpmPath = *tpmdev
	}

	if !*help && !*listtests && !*version {
		ret = run()
	} else {
		if *listtests == true {
			listTests()
		}
		if *help == true {
			showHelp()
		}
		if *version == true {
			showVersion()
		}
	}

	if ret {
		os.Exit(1)
	} else {
		os.Exit(0)
	}
}
