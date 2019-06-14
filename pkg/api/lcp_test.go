package api

import (
	"io/ioutil"
	"testing"

	"github.com/9elements/txt-suite/pkg/api"
)

func TestLCPPolicyParser(t *testing.T) {
	file, err := ioutil.ReadFile("./tests/pol.bin")
	if err != nil {
		t.Errorf("LCPPolicyParser() read failed: %v", err)
	}

	pol, err := api.ParsePolicy(file)
	if err != nil {
		t.Errorf("LCPPolicyParser() failed: %v", err)
	}

	pol.PrettyPrint()
}

func TestLCPPolicyDataParser(t *testing.T) {
	file, err := ioutil.ReadFile("./tests/poldata.bin")
	if err != nil {
		t.Errorf("LCPPolicyDataParser() failed: %v", err)
	}

	poldata, err := api.ParsePolicyData(file)
	if err != nil {
		t.Errorf("LCPPolicyDataParser() failed: %v", err)
	}

	poldata.PrettyPrint()
}
