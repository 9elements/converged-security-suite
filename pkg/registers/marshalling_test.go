package registers_test

import (
	"github.com/9elements/converged-security-suite/v2/pkg/hwapi"
	"github.com/9elements/converged-security-suite/v2/pkg/registers"
	"reflect"
	"testing"
)

type dummyMSReaderMock struct{}

func (m *dummyMSReaderMock) Read(msr int64) (uint64, error) {
	return 0, nil
}

func TestMarshalUnmarshal(t *testing.T) {
	txtAPI := hwapi.GetPcMock(func(addr uint64) byte { return hwapi.MockPCReadMemory(addr) })

	data, err := registers.FetchTXTConfigSpace(txtAPI)
	if err != nil {
		t.Errorf("FetchTXTConfigSpace() failed: %v", err)
		t.Skip()
	}

	txtRegisters, err := registers.ReadTXTRegisters(data)
	if err != nil {
		t.Errorf("ParseTXTRegs() failed: %v", err)
		t.Skip()
	}

	mock := &dummyMSReaderMock{}

	msrRegisters, err := registers.ReadMSRRegisters(mock)
	if err != nil {
		t.Skipf("ReadMSRRegisters returned an error: %v", err)
	}

	regs := append(txtRegisters, msrRegisters...)
	for _, reg := range regs {
		rawValue, err := registers.MarshalValue(reg)
		if err != nil {
			t.Errorf("failed to marhal register's %s value, err: %v", reg.ID(), err)
			continue
		}
		result, err := registers.Unmarshal(reg.ID(), rawValue)
		if err != nil {
			t.Errorf("failed to unmarhal register %s, err: %v", reg.ID(), err)
			continue
		}
		if !reflect.DeepEqual(reg, result) {
			t.Errorf("Initial register %v is not equal to restored %v", reg, result)
		}
	}
}
