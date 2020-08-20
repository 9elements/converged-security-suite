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
	"github.com/9elements/converged-security-suite/pkg/tools"
	"github.com/9elements/go-tss"
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

func run(testGroup string, tests []*test.Test, config tools.Configuration) bool {
	var result = false
	f := bufio.NewWriter(os.Stdout)

	hwAPI := hwapi.GetAPI()

	fmt.Printf("\n%s tests\n", a.Bold(a.Gray(20-1, testGroup).BgGray(4-1)))
	var i int
	for i = 0; i < len(testGroup)+6; i++ {
		fmt.Print("_")
	}
	fmt.Println()
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

		if !tests[idx].Run(hwAPI, &config) && tests[idx].Required && flagInteractive() {
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
	var config tools.Configuration
	if *configFile != "" {
		var err error
		configuration, err := tools.ParseConfig(*configFile)
		if err != nil {
			os.Exit(1)
		}
		config = *configuration
	} else {
		// Default TPM 2.0 Intel TXT configuration
		config.LCPHash = tools.LCPPol2HAlgSHA256
		config.TPM = tss.TPMVersion20
		config.TXTMode = tools.AutoPromotion
	}

	if *listtests == true {
		listTests()
	} else if *version == true {
		showVersion()
	} else if *teststomarkdown == true {
		listTestsAsMarkdown()
	} else if *all == true {
		fmt.Println("For more information about the documents and chapters, run: txt-suite -m")
		ret = run("All", getTests(), config)
	} else if *txtready == true {
		fmt.Println("For more information about the documents and chapters, run: txt-suite -m")
		ret = run("TXT Ready", test.TestsTXTReady, config)
	} else {
		fmt.Println("For more information about the documents and chapters, run: txt-suite -m")
		if *cbnt {
			fmt.Println("CBnT support not implemented yet.")
			os.Exit(1)
		} else {
			ret = run("Legacy TXT", test.TestsLegacy, config)
		}
	}
	if *uefi == true {
		ret = run("UEFI", test.TestsUEFI, config)
	}
	if *tboot == true {
		ret = run("Tboot", test.TestsTBoot, config)
	}
	if ret {
		os.Exit(1)
	} else {
		os.Exit(0)
	}
}
