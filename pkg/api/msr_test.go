package api

import (
	"testing"
)

func TestSMRR(t *testing.T) {
	has, err := HasSMRR()
	if err != nil {
		t.Errorf("HasSMRR() failed: %v", err)
	}

	if has {
		t.Log("System has SMRR")

		got, err := GetSMRRInfo()

		if err != nil {
			t.Errorf("GetSMRRInfo() failed: %v", err)
		}

		if got.active != (got.phys_base != 0 && got.phys_mask != 0) {
			t.Error("Invalid SMRR config.")
		}

		if got.active {
			t.Logf("SMRR is active. PHYS_BASE: %x, PHYS_MASK: %x", got.phys_base, got.phys_mask)
		} else {
			t.Log("SMRR is not active")
		}
	} else {
		t.Log("No SMRR")
	}
}
