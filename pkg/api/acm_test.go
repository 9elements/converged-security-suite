package api

import (
	"io/ioutil"
	"os"
	"testing"
)

func TestACMParser(t *testing.T) {
	file, err := ioutil.ReadFile("./tests/sinit_acm.bin")
	if err != nil {
		t.Errorf("ACMParser() failed: %v", err)
	}

	acm, chipsets, processors, tpms, err := ParseACM(file)
	if err != nil {
		t.Errorf("ACMParser() failed: %v", err)
	}

	acm.PrettyPrint()
	chipsets.PrettyPrint()
	processors.PrettyPrint()
	tpms.PrettyPrint()
}

func TestACMSize(t *testing.T) {
	file, err := ioutil.ReadFile("./tests/sinit_acm.bin")
	if err != nil {
		t.Errorf("ACMSize() failed: %v", err)
	}
	size, err := LookupSize(file)
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

	acm, chipsets, processors, tpms, err := ParseACM(file)
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
	size, err := LookupSize(file)
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
