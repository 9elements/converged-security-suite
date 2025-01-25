package main

import (
	"encoding/json"
	"fmt"
	"os"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/9elements/converged-security-suite/v2/pkg/test"
	"github.com/9elements/converged-security-suite/v2/pkg/tools"
	log "github.com/sirupsen/logrus"

	"github.com/9elements/go-linux-lowlevel-hw/pkg/hwapi"

	a "github.com/logrusorgru/aurora"
)

type context struct {
	interactive bool
	logpath     string
}

type listCmd struct{}

type markdownCmd struct{}

type versionCmd struct{}

type execTestsCmd struct {
	Set         string `required:"" default:"all" help:"Select subset of tests. Options: all, static, runtime, or choose tests by number e.g. --set=1,3,4"`
	Strict      bool   `required:"" default:"false" short:"s" help:"Enable strict mode. This enables more tests and checks."`
	Interactive bool   `optional:"" short:"i" help:"Interactive mode. Errors will stop the testing."`
	Config      string `optional:"" short:"c" help:"Path/Filename to config file."`
	Log         string `optional:"" help:"Give a path/filename for test result output inJSON format. e.g.: /path/to/filename.json"`
	Firmware    string `optional:"" short:"f" help:"Path/Filename to firmware to test with."`
}

var cli struct {
	ManifestStrictOrderCheck bool `help:"Enable checking of manifest elements order"`

	ExecTests execTestsCmd `cmd:"" help:"Executes tests given be TestNo or TestSet"`
	List      listCmd      `cmd:"" help:"Lists all tests"`
	Markdown  markdownCmd  `cmd:"" help:"Output test implementation state as Markdown"`
	Version   versionCmd   `cmd:"" help:"Prints the version of the program"`
}

func (e *execTestsCmd) Run(ctx *context) error {
	ret := false
	data, err := os.ReadFile(e.Firmware)
	if err != nil {
		return fmt.Errorf("can't read firmware file %v", e.Firmware)
	}
	preset := test.PreSet{
		Firmware:           data,
		HostBridgeDeviceID: 0x00,
		Strict:             e.Strict,
	}
	switch e.Set {
	case "all":
		log.Info("For more information about the documents and chapters, run: bg-suite -m")
		ret = run("All", getTests(), &preset, e.Interactive)
	case "static":
		ret = run("Static", getStaticTest(), &preset, e.Interactive)
	case "runtime":
		ret = run("Runtime", getRuntimeTest(), &preset, e.Interactive)
	default:
		var tests []*test.Test

		// Regex to detect if the set is a list of numbers
		numbers := regexp.MustCompile(`^(\d+)(,\d+)*$`)
		num := numbers.FindAllString(e.Set, -1)
		if num == nil {
			return fmt.Errorf("no valid test set given")
		}

		num = strings.Split(e.Set, ",")

		// Add Tests to the list
		for i := range num {
			testno, err := strconv.ParseUint(num[i], 10, 64)
			if err != nil {
				return fmt.Errorf("no valid test set given")
			}
			tests = append(tests, getTests()[testno])
		}

		ret = run("Custom Set", tests, &preset, e.Interactive)
	}
	if !ret {
		return fmt.Errorf("tests ran with errors")
	}
	return nil
}

func (l *listCmd) Run(ctx *context) error {
	tests := getTests()
	for i := range tests {
		log.Infof("Test No: %v, %v", i, tests[i].Name)
	}
	return nil
}

func (m *markdownCmd) Run(ctx *context) error {
	var teststate string
	tests := getTests()

	log.Info("Id | Test | Implemented | Document | Chapter")
	log.Info("------------|------------|------------|------------|------------")

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
		log.Infof("%02d | %-48s | %-22s | %-28s | %-56s", i, tests[i].Name, teststate, docID, tests[i].SpecificationChapter)
	}
	return nil
}

func (v *versionCmd) Run(ctx *context) error {
	tools.ShowVersion(programDesc, gittag, gitcommit)
	return nil
}

func getTests() []*test.Test {
	var tests []*test.Test
	for i := range test.TestsBootGuard {
		tests = append(tests, test.TestsBootGuard[i])
	}
	return tests
}

func getStaticTest() []*test.Test {
	var tests []*test.Test
	for i := range test.TestsBootGuard {
		if !strings.HasPrefix(test.TestsBootGuard[i].Name, "[RUNTIME]") {
			tests = append(tests, test.TestsBootGuard[i])
		}
	}
	return tests
}

func getRuntimeTest() []*test.Test {
	var tests []*test.Test
	for i := range test.TestsBootGuard {
		if strings.HasPrefix(test.TestsBootGuard[i].Name, "[RUNTIME]") {
			tests = append(tests, test.TestsBootGuard[i])
		}
	}
	return tests
}

func run(testGroup string, tests []*test.Test, preset *test.PreSet, interactive bool) bool {
	result := false

	hwAPI := hwapi.GetAPI()

	log.Infof("%s tests", a.Bold(a.Gray(20-1, testGroup).BgGray(4-1)))
	log.Info("--------------------------------------------------")
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

		if !tests[idx].Run(hwAPI, preset) && tests[idx].Required && interactive {
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
		err := os.WriteFile(logfile, data, 0o664)
		if err != nil {
			log.Errorf("Error writing log file: %v", err)
		}

		// If not interactive, we just print the results and return
		result = true
	}

	for index := range tests {
		var s string

		if tests[index].Status == test.NotImplemented {
			continue
		}
		if tests[index].Result == test.ResultNotRun {
			continue
		}
		s += fmt.Sprintf("%02d - ", index)
		s += fmt.Sprintf("%-40s: ", a.Bold(tests[index].Name))

		if tests[index].Result == test.ResultPass {
			s += fmt.Sprintf("%-20s", a.Bold(a.Green(tests[index].Result)))
		} else {
			s += fmt.Sprintf("%-20s", a.Bold(a.Red(tests[index].Result)))
			result = false
		}
		if tests[index].ErrorText != "" {
			s += fmt.Sprintf(" (%s)", tests[index].ErrorText)
		} else if len(tests[index].ErrorText) == 0 && tests[index].Result == test.ResultFail {
			s += fmt.Sprintf(" (No error text given)")
		}
		log.Infof("%s", s)

	}

	return result
}
