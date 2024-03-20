package tpm

import (
	"fmt"
	"unsafe"
)

func assertSameSlice[E any](a, b []E) error {
	aHdr := unsafe.SliceData(a)
	bHdr := unsafe.SliceData(b)
	if len(a) != len(b) {
		return fmt.Errorf("slices have different lengths: %d != %d", unsafe.Sizeof(a), unsafe.Sizeof(b))
	}

	if aHdr != bHdr {
		return fmt.Errorf("slice data pointers has different pointers: %X != %X", aHdr, bHdr)
	}
	return nil
}
