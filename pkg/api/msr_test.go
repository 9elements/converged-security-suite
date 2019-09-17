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

		if got.Active != (got.PhysBase != 0 && got.PhysMask != 0) {
			t.Error("Invalid SMRR config.")
		}

		if got.Active {
			t.Logf("SMRR is active. PHYS_BASE: %x, PHYS_MASK: %x", got.PhysBase, got.PhysMask)
		} else {
			t.Log("SMRR is not active")
		}
	} else {
		t.Log("No SMRR")
	}
}
