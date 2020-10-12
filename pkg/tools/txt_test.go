package tools

import (
	"testing"

	"github.com/9elements/converged-security-suite/v2/pkg/hwapi"
)

func TestTXT(t *testing.T) {
	txtAPI := hwapi.GetPcMock(func(addr uint64) byte { return hwapi.MockPCReadMemory(addr) })

	got, err := FetchTXTRegs(txtAPI)

	if err != nil {
		t.Errorf("ReadTXTRegs() failed: %v", err)
	}

	t.Logf("TXT: %+v", got)
}

func TestTxtApi_ParseTXTRegs(t *testing.T) {
	txtAPI := hwapi.GetPcMock(func(addr uint64) byte { return hwapi.MockPCReadMemory(addr) })

	data, err := FetchTXTRegs(txtAPI)

	got, err := ParseTXTRegs(data)

	if err != nil {
		t.Errorf("ParseTXTRegs() failed: %v", err)
	}

	t.Logf("TXT: %+v", got)
}

func TestReadACMStatus(t *testing.T) {

	type fields struct {
		ACMStatus [4]byte
	}

	tests := []struct {
		name          string
		fields        fields
		wantErr       bool
		wantACMStatus ACMStatus
	}{
		{
			"Invalid register",
			fields{[4]byte{0, 0, 0, 0}},
			false,
			ACMStatus{
				false,
				0,
				false,
				0,
				0,
				0,
			},
		},
		{
			"Valid register",
			fields{[4]byte{0, 0, 0, 0x80}},
			false,
			ACMStatus{
				true,
				0,
				false,
				0,
				0,
				0,
			},
		},
		{
			"Minor error",
			fields{[4]byte{0, 0, 0xaa, 0x8b}},
			false,
			ACMStatus{
				true,
				0xbaa,
				false,
				0,
				0,
				0,
			},
		},
		{
			"Major error",
			fields{[4]byte{0, 0xc, 0x00, 0x80}},
			false,
			ACMStatus{
				true,
				0,
				false,
				0x3,
				0,
				0,
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			txtAPI := hwapi.GetPcMock(func(addr uint64) byte {
				if addr >= (TxtPublicSpace+txtACMStatus) && addr < uint64(TxtPublicSpace+txtACMStatus+len(tt.fields.ACMStatus)) {
					addr -= (TxtPublicSpace + txtACMStatus)
					t.Logf("%x\n", tt.fields.ACMStatus[addr])
					return tt.fields.ACMStatus[addr]
				}
				return hwapi.MockPCReadMemory(addr)
			})

			data, err := FetchTXTRegs(txtAPI)
			if err != nil {
				t.Errorf("FetchTXTRegs() failed: %v", err)
				t.Skip()
			}
			got, err := ReadACMStatus(data)
			if err != nil && !tt.wantErr {
				t.Errorf("ReadACMStatus() failed, got unexpected error: %v", err)
			}
			if err == nil && tt.wantErr {
				t.Errorf("ReadACMStatus() failed, expected an error")
			}
			if got != tt.wantACMStatus {
				t.Errorf("Result missmatch: got %v, want %v", got, tt.wantACMStatus)
			}
		})
	}
}
