package api

import (
	"testing"
)

func TestTXT(t *testing.T) {
	got, err := ReadTXTRegs()

	if err != nil {
		t.Errorf("ReadTXTRegs() failed: %v", err)
	}

	t.Logf("TXT: %v", got)
}
