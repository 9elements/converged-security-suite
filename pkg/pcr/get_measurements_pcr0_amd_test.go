package pcr

import (
	"github.com/9elements/converged-security-suite/v2/pkg/registers"
	"reflect"
	"testing"
)

func TestMeasureMP0C2PMsgRegisters(t *testing.T) {
	inputRegisters := registers.Registers{
		registers.ParseMP0C2PMsg37Register(0x11223344),
		registers.ParseMP0C2PMsg38Register(0xaabbccdd),
	}

	ms, err := MeasureMP0C2PMsgRegisters(inputRegisters)
	if err != nil {
		t.Fatalf("unexpected error from MeasureMP0C2PMsgRegisters: '%v'", err)
	}
	if ms == nil {
		t.Fatalf("result measurement is nil")
	}

	expected := NewStaticDataMeasurement(MeasurementIDMP0C2PMsgRegisters, []byte{0x44, 0x33, 0x22, 0x11, 0xdd, 0xcc, 0xbb, 0xaa})
	if !reflect.DeepEqual(*ms, *expected) {
		t.Fatalf("expected measurment: '%v', but got '%v'", *expected, *ms)
	}
}
