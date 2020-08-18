package main

import (
	"bufio"
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"os"
	"sort"

	"github.com/9elements/converged-security-suite/pkg/hwapi"
	"github.com/9elements/converged-security-suite/pkg/test"
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

func run(tests []*test.Test) bool {
	var result = false
	f := bufio.NewWriter(os.Stdout)

	hwAPI := hwapi.GetAPI()

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

	fmt.Printf("For more information about the documents and chapters, run: txt-suite -m\n\n")
	for index := range tests {
		if tests[index].Status == test.NotImplemented {
			continue
		}
		if tests[index].Result == test.ResultNotRun {
			continue
		}
		fmt.Printf("%02d - ", index)
		fmt.Printf("%-40s: ", a.Bold(tests[index].Name))
		f.Flush()

		if tests[index].Result == test.ResultPass {
			fmt.Printf("%-20s", a.Bold(a.Green(tests[index].Result)))
		} else {
			fmt.Printf("%-20s", a.Bold(a.Red(tests[index].Result)))
		}
		if tests[index].ErrorText != "" {
			fmt.Printf(" (%s)", tests[index].ErrorText)
		} else if len(tests[index].ErrorText) == 0 && tests[index].Result == test.ResultFail {
			fmt.Print(" (No error text given)")
		}
		fmt.Printf("\n")

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
	} else if *all == true {
		ret = run(getTests())
	} else if *uefiboot == true {
		ret = run(test.TestsUEFIBoot)
	} else if *txtready == true {
		ret = run(test.TestsTXTReady)
	} else if *tboot == true {
		ret = run(test.TestsTBoot)
	} else {
		ret = run(test.TestsBIOSBoot)
	}

	if ret {
		os.Exit(1)
	} else {
		os.Exit(0)
	}
}
