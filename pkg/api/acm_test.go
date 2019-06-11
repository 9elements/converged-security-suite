package api

import (
	"io/ioutil"
	"testing"

	"github.com/9elements/txt-suite/pkg/api"
)

func TestACMParser(t *testing.T) {
	file, err := ioutil.ReadFile("./tests/sinit_acm.bin")
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

func TestACMSize(t *testing.T) {
	file, err := ioutil.ReadFile("./tests/sinit_acm.bin")
	if err != nil {
		t.Errorf("ACMSize() failed: %v", err)
	}

	size, err := api.LookupSize(file)
	if err != nil {
		t.Errorf("ACMSize() failed: %v", err)
	}

	if size != 32768 {
		t.Errorf("ACMSize() failed: Wrong size returned")
	}
}
