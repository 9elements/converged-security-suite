package cbnt

import (
	"fmt"
	"io/ioutil"
	"strings"

	"github.com/9elements/converged-security-suite/v2/pkg/intel/metadata/manifest"

	"github.com/9elements/converged-security-suite/v2/pkg/intel/metadata/manifest/bootpolicy"
	"github.com/9elements/converged-security-suite/v2/pkg/intel/metadata/manifest/key"

	a "github.com/logrusorgru/aurora"
)

type testObj struct {
	image     []byte
	kmpubkey  *manifest.Key
	bpmpubkey *manifest.Key
	km        *key.Manifest
	bpm       *bootpolicy.Manifest
}

var (
	bpmpubkeypath string
	objUnderTest  testObj
)

type result int

const (
	resultError result = iota
	resultNotRun
	resultValid
	resultWarning
)

type testType int

const (
	required testType = iota
	txte
	pcde
	pme
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
	default:
		_, err = s.WriteString("Result is a unknown state")
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
	Type      testType
}

// Run defines the execution of a Test
func (t *Test) Run() bool {
	res := false
	res, err := t.function()
	if err != nil {
		t.ErrorText = err.Error()
	}
	if res && err == nil {
		t.Result = resultValid
	} else if res && err != nil {
		t.Result = resultWarning
	}
	return res
}

func setObjUnderTest(imgpath string, kmkeypath string, bpmkeypath string) error {
	// Read the image
	img, err := ioutil.ReadFile(imgpath)
	if err != nil {
		return err
	}
	// Read the KM public key and put it in manifest.Key structure
	k, err := ReadPubKey(kmkeypath)
	if err != nil {
		return err
	}
	kmkey := manifest.NewKey()
	if err := kmkey.SetPubKey(k); err != nil {
		return err
	}

	// Read the BPM public key and put it in manifest.Key structure
	b, err := ReadPubKey(bpmkeypath)
	if err != nil {
		return err
	}
	bpmkey := manifest.NewKey()
	if err := bpmkey.SetPubKey(b); err != nil {
		return err
	}
	// Extract KM & BPM structures
	bpmEntry, kmEntry, _, err := ParseFITEntries(img)
	if err != nil {
		return err
	}
	tbpm, err := bpmEntry.ParseData()
	if err != nil {
		return err
	}
	tkm, err := kmEntry.ParseData()
	if err != nil {
		return err
	}
	t := testObj{
		image:     img,
		kmpubkey:  kmkey,
		bpmpubkey: bpmkey,
		km:        tkm,
		bpm:       tbpm,
	}

	objUnderTest = t
	return nil
}

// ValidateImage takes a path to a firmware image and validates it in regard of CBnT
func ValidateImage(imgpath, bpmkeypath, kmkeypath string, interactive bool) error {
	if err := setObjUnderTest(imgpath, kmkeypath, bpmkeypath); err != nil {
		return nil
	}
	// We need that for one function.
	//ToDo: Create better solution
	bpmpubkeypath = bpmkeypath
	tests := append(imageKMTests, imageBPMTests...)
	tests = append(tests, imageCrossTests...)

	for idx, test := range tests {
		skip := false
		switch test.Type {
		case txte:
			if objUnderTest.bpm.TXTE == nil {
				test.Result = resultNotRun
				test.ErrorText = "Structure not present"
				skip = true
			}
		case pcde:
			if objUnderTest.bpm.PCDE == nil {
				test.Result = resultNotRun
				test.ErrorText = "Structure not present"
				skip = true
			}
		case pme:
			if objUnderTest.bpm.PME == nil {
				test.Result = resultNotRun
				test.ErrorText = "Structure not present"
				skip = true
			}
		}
		if !skip {
			test.Run()
			fmt.Printf("| %-35s ", tests[idx].Name)
			if tests[idx].Result == resultValid {
				fmt.Printf(" %-10s | ", a.Bold(a.Green(tests[idx].Result.String())))
			} else if tests[idx].Result == resultWarning {
				fmt.Printf(" %-10s | ", a.Bold(a.Yellow(tests[idx].Result.String())))
			} else if tests[idx].Result == resultError {
				fmt.Printf(" %-10s | ", a.Bold(a.Red(tests[idx].Result.String())))
			}

			if tests[idx].ErrorText != "" {
				fmt.Printf("%-20s ", tests[idx].ErrorText)
			}
			fmt.Printf("\n-----------------------------------------------------------------------------------------------------------\n")

			if interactive {
				fmt.Println("Press enter to continue testing")
				fmt.Scanln()
			}
		}

	}
	return nil
}
