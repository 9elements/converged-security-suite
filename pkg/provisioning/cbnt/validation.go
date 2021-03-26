package cbnt

import (
	"fmt"
	"io/ioutil"
	"strings"

	"github.com/9elements/converged-security-suite/v2/pkg/intel/metadata/fit"

	"github.com/9elements/converged-security-suite/v2/pkg/intel/metadata/manifest/bootpolicy"
	"github.com/9elements/converged-security-suite/v2/pkg/intel/metadata/manifest/key"
)

var (
	image         []byte
	km            *key.Manifest
	bpm           *bootpolicy.Manifest
	fitkm         fit.EntryHeaders
	bpmpubkeypath string
	kmpubkeypath  string
)

type result int

const (
	resultError result = iota
	resultNotRun
	resultValid
	resultWarning
)

func (r result) String() string {
	var s strings.Builder
	var err error
	switch r {
	case resultError:
		_, err = s.WriteString("Error")
	case resultNotRun:
		_, err = s.WriteString("Not run!")
	case resultValid:
		_, err = s.WriteString("Valid")
	case resultWarning:
		_, err = s.WriteString("Warning")
	}
	if err != nil {
		return fmt.Sprintf("error in s.WriteString(): %v", err)
	}
	return s.String()
}

// Test represents a Test for a CBnT enabled firmware image
type Test struct {
	Name      string
	function  func() (bool, error)
	Result    result
	ErrorText string
}

// Run defines the execution of a CBnTTest
func (t *Test) Run() bool {
	var res = false
	res, err := t.function()
	if err != nil {
		t.ErrorText = err.Error()
	}
	if res == true && err == nil {
		t.Result = resultValid
	} else if res == true && err != nil {
		t.Result = resultWarning
	}
	return res
}

// ValidateImage takes a path to a firmware image and validates it in regard of CBnT
func ValidateImage(imgpath, bpmkeypath, kmkeypath string, interactive bool) error {
	var err error
	image, err = ioutil.ReadFile(imgpath)
	if err != nil {
		return err
	}
	bpmpubkeypath = bpmkeypath
	kmpubkeypath = kmkeypath

	bpmEntry, kmEntry, _, err := ParseFITEntries(image)
	if err != nil {
		return err
	}
	bpm, err = bpmEntry.ParseData()
	if err != nil {
		return err
	}
	km, err = kmEntry.ParseData()

	for idx := range ImageBPMTests {
		ImageBPMTests[idx].Run()
		fmt.Printf("Test %s: %v ", ImageBPMTests[idx].Name, ImageBPMTests[idx].Result.String())
		if ImageBPMTests[idx].ErrorText != "" {
			fmt.Printf("- %v", ImageBPMTests[idx].ErrorText)
		}
		fmt.Println(" ")

		if interactive {
			fmt.Println("Press enter to continue testing")
			fmt.Scanln()
		}
	}
	return nil
}
