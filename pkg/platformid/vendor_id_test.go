package platformid

import (
	"strings"
	"testing"

	"github.com/klauspost/cpuid/v2"
)

func TestVendorIDString(t *testing.T) {
	for vid := VendorIDUndefined; vid < EndOfVendorID; vid++ {
		if strings.Contains(vid.String(), "unknown") {
			t.Fatalf("vid %d has no String", vid)
		}
	}
}

func TestVendorIDCPUVendorID(t *testing.T) {
	for vid := VendorIDUndefined + 1; vid < EndOfVendorID; vid++ {
		if vid.CPUVendorID() == cpuid.VendorUnknown {
			t.Fatalf("vid %d has no CPUVendorID", vid)
		}
	}
}
