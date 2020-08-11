package tools

import (
	"crypto"
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
	var lcp2 *LCPPolicy2
	file, err := ioutil.ReadFile("./tests/pol3.bin")
	if err != nil {
		t.Errorf("LCPDataParser() failed: %v", err)
	}

	_, lcp2, err = ParsePolicy(file)
	if err != nil {
		t.Errorf("LCPDataParser() failed: %v", err)
	}
	lcp2.PrettyPrint()
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

func TestLCPPolv2Gen(t *testing.T) {
	version := uint16(0x304)
	sinitmin := uint8(0)
	hash := make([]byte, crypto.SHA256.Size())
	apprHash := ApprovedHashAlgorithm{SHA1: false, SHA256: true, SHA384: false, SM3: false}
	apprSign := ApprovedSignatureAlogrithm{RSA3072SHA256: true}
	pc := PolicyControl{NPW: false, OwnerEnforced: false, AuxDelete: false, SinitCaps: false}
	lcp2, err := GenLCPPolicyV2(version, crypto.SHA256, hash, sinitmin, pc, apprHash, apprSign)
	if err != nil {
		t.Errorf("GenLCPPolicyV2() failed: %v", err)
	}
	lcp2.PrettyPrint()
}
