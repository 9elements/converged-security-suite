package tpm

import (
	"fmt"
	"reflect"
	"unsafe"
)

func assertSameSlice[E any](a, b []E) error {
	aHdr := (*reflect.SliceHeader)(unsafe.Pointer(&a))
	bHdr := (*reflect.SliceHeader)(unsafe.Pointer(&b))
	if aHdr.Len != bHdr.Len {
		return fmt.Errorf("slices have different lengths: %d != %d", aHdr.Len, bHdr.Len)
	}
	if aHdr.Data != bHdr.Data {
		return fmt.Errorf("slice data pointers has different pointers: %X != %X", aHdr.Data, bHdr.Data)
	}
	return nil
}
