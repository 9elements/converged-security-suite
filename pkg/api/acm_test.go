package api

import (
	"io/ioutil"
	"os"
	"testing"
)

func TestParseandValidateACMHeader(t *testing.T) {
	file, err := ioutil.ReadFile("./tests/sinit_acm.bin")
	if err != nil {
		t.Errorf("Failed to read file: %v", err)
	}

	txtAPI := GetApi()

	header, err := txtAPI.ParseACMHeader(file)
	if err != nil {
		t.Errorf("ParseACMHeader() failed: %v", err)
	}

	valid, err := txtAPI.ValidateACMHeader(header)
	if err != nil {
		t.Errorf("ValidateACMHeader() failed: %v", err)
	}
	if !valid {
		t.Errorf("ValidateACMHeader() failed to validate the ACMHeader")
	}

	header.PrettyPrint()
}

func TestACMParser(t *testing.T) {
	file, err := ioutil.ReadFile("./tests/sinit_acm.bin")
	if err != nil {
		t.Errorf("Failed to read file: %v", err)
	}
	txtAPI := GetApi()

	acm, chipsets, processors, tpms, err := txtAPI.ParseACM(file)
	if err != nil {
		t.Errorf("ParseACM() failed: %v", err)
	}

	acm.PrettyPrint()
	chipsets.PrettyPrint()
	processors.PrettyPrint()
	tpms.PrettyPrint()
}

func TestACMSize(t *testing.T) {
	file, err := ioutil.ReadFile("./tests/sinit_acm.bin")
	if err != nil {
		t.Errorf("Failed to read file: %v", err)
	}
	txtAPI := GetApi()

	size, err := txtAPI.LookupSize(file)
	if err != nil {
		t.Errorf("ACMSize() failed: %v", err)
	}
	fh, err := os.Open("./tests/sinit_acm.bin")
	if err != nil {
		t.Errorf("ACMSize() failed: %v", err)
	}
	st, _ := fh.Stat()
	if size != st.Size() {
		t.Errorf("ACMSize() failed: Wrong size returned, %d", size)
	}
}

func TestACMParser2(t *testing.T) {
	file, err := ioutil.ReadFile("./tests/bios_acm.bin")
	if err != nil {
		t.Errorf("ACMParser() failed: %v", err)
	}
	txtAPI := GetApi()

	acm, chipsets, processors, tpms, err := txtAPI.ParseACM(file)
	if err != nil {
		t.Errorf("ACMParser() failed: %v", err)
	}

	acm.PrettyPrint()
	chipsets.PrettyPrint()
	processors.PrettyPrint()
	tpms.PrettyPrint()
}

func TestACMSize2(t *testing.T) {
	file, err := ioutil.ReadFile("./tests/bios_acm.bin")
	if err != nil {
		t.Errorf("ACMSize() failed: %v", err)
	}
	txtAPI := GetApi()

	size, err := txtAPI.LookupSize(file)
	if err != nil {
		t.Errorf("ACMSize() failed: %v", err)
	}
	fh, err := os.Open("./tests/sinit_acm.bin")
	if err != nil {
		t.Errorf("ACMSize() failed: %v", err)
	}
	st, _ := fh.Stat()
	if size != st.Size() {
		t.Errorf("ACMSize() failed: Wrong size returned, %d", size)
	}
}
