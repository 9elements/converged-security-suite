package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"
	"sort"

	"github.com/9elements/converged-security-suite/v2/pkg/test"
	"github.com/9elements/converged-security-suite/v2/pkg/tools"
	"github.com/google/go-tpm/tpm2"

	"github.com/9elements/converged-security-suite/v2/pkg/hwapi"

	a "github.com/logrusorgru/aurora"
)

type context struct {
	tpmdev      *hwapi.TPM
	interactive bool
	logpath     string
}

type listCmd struct {
}

type markdownCmd struct {
}

type versionCmd struct {
}

type execTestsCmd struct {
	Set         string `required default:"all" help:"Select subset of tests. Options: all, uefi, txtready, tboot, cbnt, legacy"`
	Interactive bool   `optional short:"i" help:"Interactive mode. Errors will stop the testing."`
	Config      string `optional short:"c" help:"Path/Filename to config file."`
	Log         string `optional help:"Give a path/filename for test result output inJSON format. e.g.: /path/to/filename.json"`
}

var cli struct {
	ManifestStrictOrderCheck bool `help:"Enable checking of manifest elements order"`

	TpmDev string `short:"t" help:"Select TPM-Path. e.g.:--tpmdev=/dev/tpmX, with X as number of the TPM module"`

	ExecTests execTestsCmd `cmd help:"Executes tests given be TestNo or TestSet"`
	List      listCmd      `cmd help:"Lists all tests"`
	Markdown  markdownCmd  `cmd help:"Output test implementation state as Markdown"`
	Version   versionCmd   `cmd help:"Prints the version of the program"`
}

func (e *execTestsCmd) Run(ctx *context) error {
	ret := false
	var config tools.Configuration
	if e.Config != "" {
		var err error
		configuration, err := tools.ParseConfig(e.Config)
		if err != nil {
			os.Exit(1)
		}
		config = *configuration
	} else {
		// Default TPM 2.0 Intel TXT configuration
		config.LCPHash = tpm2.AlgSHA256
		config.TPM = hwapi.TPMVersion20
		config.TXTMode = tools.AutoPromotion
	}

	switch e.Set {
	case "all":
		fmt.Println("For more information about the documents and chapters, run: txt-suite -m")
		ret = run("All", getTests(), config, e.Interactive)
	case "uefi":
		ret = run("UEFI", test.TestsUEFI, config, e.Interactive)
	case "txtready":
		fmt.Println("For more information about the documents and chapters, run: txt-suite -m")
		ret = run("TXT Ready", test.TestsTXTReady, config, e.Interactive)
	case "tboot":
		ret = run("Tboot", test.TestsTBoot, config, e.Interactive)
	case "cbnt":
		return fmt.Errorf("CBnT support not implemented yet")
	case "legacy":
		ret = run("Legacy TXT", test.TestsLegacy, config, e.Interactive)
	default:
		return fmt.Errorf("No valid test set given")
	}
	if !ret {
		return fmt.Errorf("Tests ran with errors")
	}
	return nil
}

func (l *listCmd) Run(ctx *context) error {
	tests := getTests()
	for i := range tests {
		fmt.Printf("Test No: %v, %v\n", i, tests[i].Name)
	}
	return nil
}

func (m *markdownCmd) Run(ctx *context) error {
	var teststate string
	tests := getTests()

	fmt.Println("Id | Test | Implemented | Document | Chapter")
	fmt.Println("------------|------------|------------|------------|------------")
	for i := range tests {
		if tests[i].Status == test.Implemented {
			teststate = ":white_check_mark:"
		} else if tests[i].Status == test.NotImplemented {
			teststate = ":x:"
		} else {
			teststate = ":clock1:"
		}
		docID := tests[i].SpecificationDocumentID
		if docID != "" {
			docID = "Document " + docID
		}
		fmt.Printf("%02d | %-48s | %-22s | %-28s | %-56s\n", i, tests[i].Name, teststate, docID, tests[i].SpecificationChapter)
	}
	return nil
}

func (v *versionCmd) Run(ctx *context) error {
	tools.ShowVersion(programDesc, gittag, gitcommit)
	return nil
}

func getTests() []*test.Test {
	var tests []*test.Test
	for i := range test.TestsCPU {
		tests = append(tests, test.TestsCPU[i])
	}
	for i := range test.TestsTPM {
		tests = append(tests, test.TestsTPM[i])
	}
	for i := range test.TestsFIT {
		tests = append(tests, test.TestsFIT[i])
	}
	for i := range test.TestsMemory {
		tests = append(tests, test.TestsMemory[i])
	}
	for i := range test.TestsACPI {
		tests = append(tests, test.TestsACPI[i])
	}
	return tests
}

func run(testGroup string, tests []*test.Test, config tools.Configuration, interactive bool) bool {
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

		if !tests[idx].Run(hwAPI, &config) && tests[idx].Required && interactive {
			result = true
			break
		}

	}

	if !interactive {
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
