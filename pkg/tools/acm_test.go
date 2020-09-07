package tools

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

	header, err := ParseACMHeader(file)
	if err != nil {
		t.Errorf("ParseACMHeader() failed: %v", err)
	}

	valid, err := ValidateACMHeader(header)
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

	acm, chipsets, processors, tpms, err, internalerr := ParseACM(file)
	if internalerr != nil {
		t.Errorf("ACMParser() failed with internal error: %v", err)
	}
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

	size, err := LookupACMSize(file)
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

	acm, chipsets, processors, tpms, err, internalerr := ParseACM(file)
	if internalerr != nil {
		t.Errorf("ACMParser() failed with internal error: %v", err)
	}
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

	size, err := LookupACMSize(file)
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
