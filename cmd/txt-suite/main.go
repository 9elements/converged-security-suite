package main

import (
	"bufio"
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"os"
	"sort"

	"github.com/9elements/txt-suite/pkg/hwapi"
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

func run() bool {
	var result = false
	var tests []*test.Test
	f := bufio.NewWriter(os.Stdout)

	hwAPI := hwapi.GetApi()

	tests = getTests()

	for idx := range tests {
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

		if !tests[idx].Run(hwAPI) && tests[idx].Required && flagInteractive() {
			result = true
			break
		}

	}

	if !flagInteractive() {
		var t []temptest
		for index := range tests {
			if tests[index].Status != test.NotImplemented {
				ttemp := temptest{index, tests[index].Name, tests[index].Result.String(), tests[index].ErrorText, tests[index].Status.String()}
				t = append(t, ttemp)
			}
		}
		data, _ := json.MarshalIndent(t, "", "")
		ioutil.WriteFile(logfile, data, 0664)
	}

	for index := range tests {
		if tests[index].Status == test.NotImplemented {
			continue
		}
		if tests[index].Result == test.ResultNotRun {
			continue
		}
		fmt.Printf("%-40s: ", a.Bold(tests[index].Name))
		f.Flush()

		if tests[index].Result == test.ResultPass {
			fmt.Printf("%-20s\n", a.Bold(a.Green(tests[index].Result)))
		} else if tests[index].Result == test.ResultWarn {
			fmt.Printf("%-20s\n", a.Bold(a.Yellow(tests[index].Result)))
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

	if *logpath != "" {
		logfile = *logpath
	}

	if *listtests == true {
		listTests()
	} else if *help == true {
		showHelp()
	} else if *version == true {
		showVersion()
	} else if *teststomarkdown == true {
		listTestsAsMarkdown()
	} else {
		ret = run()
	}

	if ret {
		os.Exit(1)
	} else {
		os.Exit(0)
	}
}
