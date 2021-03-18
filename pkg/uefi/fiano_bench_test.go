package uefi

import (
	"testing"

	"github.com/9elements/converged-security-suite/v2/testdata/firmware"
	fianoUEFI "github.com/linuxboot/fiano/pkg/uefi"
)

// BenchmarkFianoUEFIParse-8             36          31644656 ns/op        33555652 B/op         12 allocs/op
func BenchmarkFianoUEFIParse(b *testing.B) {
	firmwareBytes, err := firmware.GetTestImage("../../testdata/firmware/GALAGOPRO3.fd.xz")
	if err != nil {
		panic(err)
	}

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = fianoUEFI.Parse(firmwareBytes)
	}
}
