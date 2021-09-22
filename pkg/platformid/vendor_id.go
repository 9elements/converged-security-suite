package platformid

import (
	"fmt"

	"github.com/klauspost/cpuid/v2"
)

// VendorID is an unique ID of a platform vendor.
//
// It differs from github.com/klauspost/cpuid.Vendor, because cpuid.Vendor
// defines CPU vendor, while a platform may combine for example
// Intel and Lattice (and this combination will have an additional ID).
type VendorID int

const (
	// VendorIDUndefined is a VendorID reserved for the zero-value only.
	VendorIDUndefined = VendorID(iota)

	// VendorIDIntel is a vendor ID corresponds to "Intel".
	VendorIDIntel

	// VendorIDAMD is a vendor ID corresponds to "AMD".
	VendorIDAMD

	// EndOfVendorID is a limiter for loops to iterate over VendorID-s.
	EndOfVendorID
)

// String implements fmt.Stringer.
func (vid VendorID) String() string {
	switch vid {
	case VendorIDUndefined:
		return "<undefined>"
	case VendorIDIntel:
		return "Intel"
	case VendorIDAMD:
		return "AMD"
	}
	return fmt.Sprintf("unknown_VendorID_%d", vid)
}

// CPUVendorID return the vendor ID of the CPU used on the platform.
func (vid VendorID) CPUVendorID() cpuid.Vendor {
	switch vid {
	case VendorIDIntel:
		return cpuid.Intel
	case VendorIDAMD:
		return cpuid.AMD
	}
	return cpuid.VendorUnknown
}
