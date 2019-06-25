package api

import (
	"io/ioutil"
	"testing"

	"github.com/9elements/txt-suite/pkg/api"
)

func TestLCPParser(t *testing.T) {
	file, err := ioutil.ReadFile("./tests/pol.bin")
	if err != nil {
		t.Fatalf("LCPParser() read failed: %v", err)
	}

	pol, err := api.ParsePolicy(file)
	if err != nil {
		t.Fatalf("LCPParser() failed: %v", err)
	}

	pol.PrettyPrint()
}

func TestLCPDataParser(t *testing.T) {
	file, err := ioutil.ReadFile("./tests/poldata.bin")
	if err != nil {
		t.Fatalf("LCPDataParser() failed: %v", err)
	}

	poldata, err := api.ParsePolicyData(file)
	if err != nil {
		t.Fatalf("LCPDataParser() failed: %v", err)
	}

	poldata.PrettyPrint()
}

func TestLCPDataParser2(t *testing.T) {
	file, err := ioutil.ReadFile("./tests/poldata2.bin")
	if err != nil {
		t.Fatalf("LCPDataParser() failed: %v", err)
	}

	poldata, err := api.ParsePolicyData(file)
	if err != nil {
		t.Fatalf("LCPDataParser() failed: %v", err)
	}

	poldata.PrettyPrint()
}
