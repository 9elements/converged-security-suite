package api

import (
	"io/ioutil"
	"testing"
)

func TestLCPParser(t *testing.T) {
	file, err := ioutil.ReadFile("./tests/pol.bin")
	if err != nil {
		t.Errorf("LCPParser() read failed: %v", err)
	}

	_, _, err = ParsePolicy(file)
	if err != nil {
		t.Errorf("LCPParser() failed: %v", err)
	}
}

func TestLCPParser2(t *testing.T) {
	file, err := ioutil.ReadFile("./tests/pol2.bin")
	if err != nil {
		t.Errorf("LCPParser() read failed: %v", err)
	}

	_, _, err = ParsePolicy(file)
	if err != nil {
		t.Errorf("LCPParser() failed: %v", err)
	}
}

func TestLCPParser3(t *testing.T) {
	file, err := ioutil.ReadFile("./tests/pol3.bin")
	if err != nil {
		t.Errorf("LCPDataParser() failed: %v", err)
	}

	_, _, err = ParsePolicy(file)
	if err != nil {
		t.Errorf("LCPDataParser() failed: %v", err)
	}
}

func TestLCPDataParser(t *testing.T) {
	file, err := ioutil.ReadFile("./tests/poldata.bin")
	if err != nil {
		t.Errorf("LCPDataParser() failed: %v", err)
	}

	poldata, err := ParsePolicyData(file)
	if err != nil {
		t.Errorf("LCPDataParser() failed: %v", err)
	}

	poldata.PrettyPrint()
}

func TestLCPDataParser2(t *testing.T) {
	file, err := ioutil.ReadFile("./tests/poldata2.bin")
	if err != nil {
		t.Errorf("LCPDataParser() failed: %v", err)
	}

	poldata, err := ParsePolicyData(file)
	if err != nil {
		t.Errorf("LCPDataParser() failed: %v", err)
	}

	poldata.PrettyPrint()
}
