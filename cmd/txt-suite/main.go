package main

import (
	"encoding/json"
	"flag"
	"io/ioutil"
	"os"
	"sort"

	"github.com/9elements/txt-suite/pkg/test"
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
