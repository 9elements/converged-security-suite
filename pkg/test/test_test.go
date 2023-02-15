package test

import (
	"fmt"
	"testing"

	"github.com/9elements/converged-security-suite/v2/pkg/tools"
	"github.com/9elements/go-linux-lowlevel-hw/pkg/hwapi"
	"github.com/google/go-tpm/tpm2"
)

func TestTest_Run(t *testing.T) {
	type fields struct {
		Name         string
		Required     bool
		function     func(hwapi.LowLevelHardwareInterfaces, *PreSet) (bool, error, error)
		Result       Result
		dependencies []*Test
		ErrorText    string
		Status       Status
	}

	BNotImplemented := Test{
		"Test B",
		true,
		func(a hwapi.LowLevelHardwareInterfaces, p *PreSet) (bool, error, error) {
			return true, nil, nil
		},
		ResultFail,
		nil,
		"",
		"",
		NotImplemented,
		"",
		"",
		"",
	}

	BFailed := Test{
		"Test B",
		true,
		func(a hwapi.LowLevelHardwareInterfaces, p *PreSet) (bool, error, error) {
			return true, nil, nil
		},
		ResultFail,
		nil,
		"",
		"",
		Implemented,
		"",
		"",
		"",
	}
	BNotRun := Test{
		"Test B",
		true,
		func(a hwapi.LowLevelHardwareInterfaces, p *PreSet) (bool, error, error) {
			return true, nil, nil
		},
		ResultNotRun,
		nil,
		"",
		"",
		Implemented,
		"",
		"",
		"",
	}

	tests := []struct {
		name       string
		fields     fields
		wantReturn bool
		wantResult Result
	}{
		{
			"Dependency not implemented",
			fields{
				"Test A, ignores unimplemented Test B",
				true,
				func(a hwapi.LowLevelHardwareInterfaces, p *PreSet) (bool, error, error) {
					return true, nil, nil
				},
				ResultNotRun,
				[]*Test{&BNotImplemented},
				"",
				Implemented,
			},
			true,
			ResultPass,
		},
		{
			"Dependency failed",
			fields{
				"Test A, fails on failed dependency Test B",
				true,
				func(a hwapi.LowLevelHardwareInterfaces, p *PreSet) (bool, error, error) {
					return true, nil, nil
				},
				ResultNotRun,
				[]*Test{&BFailed},
				"",
				Implemented,
			},
			false,
			ResultDependencyFailed,
		},
		{
			"Dependency not run",
			fields{
				"Test A, runs dependency Test B",
				true,
				func(a hwapi.LowLevelHardwareInterfaces, p *PreSet) (bool, error, error) {
					return BNotRun.Result == ResultPass, nil, nil
				},
				ResultNotRun,
				[]*Test{&BNotRun},
				"",
				Implemented,
			},
			true,
			ResultPass,
		},
		{
			"Multiple dependencies",
			fields{
				"Test A, multiple dependencies",
				true,
				func(a hwapi.LowLevelHardwareInterfaces, p *PreSet) (bool, error, error) {
					return BNotRun.Result == ResultPass, nil, nil
				},
				ResultNotRun,
				[]*Test{&BNotRun, &BNotImplemented},
				"",
				Implemented,
			},
			true,
			ResultPass,
		},
		{
			"Internal error",
			fields{
				"Test A, returns internal error",
				true,
				func(a hwapi.LowLevelHardwareInterfaces, p *PreSet) (bool, error, error) {
					return true, nil, fmt.Errorf("Internal error 24")
				},
				ResultNotRun,
				[]*Test{},
				"",
				Implemented,
			},
			false,
			ResultInternalError,
		},
		{
			"Regular test error",
			fields{
				"Test A, returns error",
				true,
				func(a hwapi.LowLevelHardwareInterfaces, p *PreSet) (bool, error, error) {
					return true, fmt.Errorf("error 1"), nil
				},
				ResultNotRun,
				[]*Test{},
				"",
				Implemented,
			},
			false,
			ResultFail,
		},
		{
			"Regular test error critical",
			fields{
				"Test A, returns error, but is critical",
				true,
				func(a hwapi.LowLevelHardwareInterfaces, p *PreSet) (bool, error, error) {
					return false, fmt.Errorf("error 1"), nil
				},
				ResultNotRun,
				[]*Test{},
				"",
				Implemented,
			},
			false,
			ResultFail,
		},
	}
	hw := hwapi.GetAPI()
	var preset PreSet
	preset.TPM = hwapi.TPMVersion20
	preset.TXTMode = tools.AutoPromotion
	preset.LCPHash = tpm2.AlgSHA256
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tr := &Test{
				Name:         tt.fields.Name,
				Required:     tt.fields.Required,
				function:     tt.fields.function,
				Result:       tt.fields.Result,
				dependencies: tt.fields.dependencies,
				ErrorText:    tt.fields.ErrorText,
				Status:       tt.fields.Status,
			}
			if got := tr.Run(hw, &preset); got != tt.wantReturn {
				t.Errorf("Test.Run() = %v, want %v", got, tt.wantReturn)
			}
			if tr.Result != tt.wantResult {
				t.Errorf("Test.Result = %v, want %v", tr.Result, tt.wantResult)
			}
		})
	}
}
