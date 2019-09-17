package api

import (
	"testing"
)

func TestTXT(t *testing.T) {
	t.Skip()
	got, err := FetchTXTRegs()

	if err != nil {
		t.Errorf("ReadTXTRegs() failed: %v", err)
	}

	t.Logf("TXT: %+v", got)
}
