package api

import (
	"testing"
)

func TestSMRR(t *testing.T) {
	got, err := GetSMRRInfo()

	if err != nil {
		t.Errorf("GetSMRRInfo() failed: %v", err)
	}

	if got.valid != (got.phys_base == 0 || got.phys_mask == 0) {
		t.Error("Invalid SMRR config.")
	}

	if got.valid {
		t.Logf("SMRR is active. PHYS_BASE: %x, PHYS_MASK: %x", got.phys_base, got.phys_mask)
	} else {
		t.Log("SMRR is not active")
	}
}
