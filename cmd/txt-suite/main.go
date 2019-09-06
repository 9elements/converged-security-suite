package main

import (
	"encoding/json"
	"flag"
	"io/ioutil"
	"os"
	"sort"
	"fmt"
	"bufio"

	"github.com/9elements/txt-suite/pkg/test"
	a "github.com/logrusorgru/aurora"
)

var (
	testnos []int
	testerg bool
	logfile = "test_log.json"
)

type temptest struct {
	Testnumber int
	Testname   string
	Result     string
	Error      string
	Status     string
}

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
	f := bufio.NewWriter(os.Stdout)

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

	if stayAlive() {
		var t []temptest
		for index, _ := range tests {
			if tests[index].Status != test.TestNotImplemented {
				ttemp := temptest{index, tests[index].Name, tests[index].Result.String(), tests[index].ErrorText, tests[index].Status.String()}
				t = append(t, ttemp)
			}
		}
		data, _ := json.MarshalIndent(t, "", "")
		ioutil.WriteFile(logfile, data, 0664)
	}

	for index, _ := range tests {
		if tests[index].Status == test.TestNotImplemented {
			continue
		}
		if tests[index].Result == test.ResultNotRun {
			continue
		}
		fmt.Printf("%-40s: ", a.Bold(tests[index].Name))
		f.Flush()

		if tests[index].Result == test.ResultPass {
			fmt.Printf("%-20s\n", a.Bold(a.Green(tests[index].Result)))
		} else {
			fmt.Printf("%-20s\n", a.Bold(a.Red(tests[index].Result)))
		}
		if tests[index].ErrorText != "" {
			fmt.Printf(" %s\n\n", tests[index].ErrorText)
		}
		f.Flush()
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

	if *logpath != "" {
		logfile = *logpath
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
