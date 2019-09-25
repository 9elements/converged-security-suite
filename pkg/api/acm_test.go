package api

import (
	"io/ioutil"
	"os"
	"testing"

	"github.com/9elements/txt-suite/pkg/api"
)

func TestParseandValidateACMHeader(t *testing.T) {
	file, err := ioutil.ReadFile("./tests/sinit_acm.bin")
	if err != nil {
		t.Errorf("Failed to read file: %v", err)
	}

	header, err := api.ParseACMHeader(file)
	if err != nil {
		t.Errorf("ParseACMHeader() failed: %v", err)
	}

	valid, err := api.ValidateACMHeader(header)
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

	acm, chipsets, processors, tpms, err := api.ParseACM(file)
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
	size, err := api.LookupSize(file)
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

	acm, chipsets, processors, tpms, err := api.ParseACM(file)
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
	size, err := api.LookupSize(file)
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
