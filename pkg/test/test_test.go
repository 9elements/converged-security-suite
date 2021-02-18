package test

import (
	"fmt"
	"testing"

	"github.com/google/go-tpm/tpm2"

	"github.com/9elements/converged-security-suite/v2/pkg/hwapi"
	"github.com/9elements/converged-security-suite/v2/pkg/tools"
)

func TestTest_Run(t *testing.T) {
	type fields struct {
		Name         string
		Required     bool
		function     func(hwapi.APIInterfaces, *tools.Configuration) (bool, error, error)
		Result       Result
		dependencies []*Test
		ErrorText    string
		Status       Status
		Spec         TXTSpec
	}

	BNotImplemented := Test{
		"Test B",
		true,
		func(a hwapi.APIInterfaces, c *tools.Configuration) (bool, error, error) { return true, nil, nil },
		ResultFail,
		nil,
		"",
		"",
		NotImplemented,
		Common,
		"",
		"",
		"",
	}

	BFailed := Test{
		"Test B",
		true,
		func(a hwapi.APIInterfaces, c *tools.Configuration) (bool, error, error) { return true, nil, nil },
		ResultFail,
		nil,
		"",
		"",
		Implemented,
		Common,
		"",
		"",
		"",
	}
	BNotRun := Test{
		"Test B",
		true,
		func(a hwapi.APIInterfaces, c *tools.Configuration) (bool, error, error) { return true, nil, nil },
		ResultNotRun,
		nil,
		"",
		"",
		Implemented,
		Common,
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
				func(a hwapi.APIInterfaces, c *tools.Configuration) (bool, error, error) { return true, nil, nil },
				ResultNotRun,
				[]*Test{&BNotImplemented},
				"",
				Implemented,
				Common,
			},
			true,
			ResultPass,
		},
		{
			"Dependency failed",
			fields{
				"Test A, fails on failed dependency Test B",
				true,
				func(a hwapi.APIInterfaces, c *tools.Configuration) (bool, error, error) { return true, nil, nil },
				ResultNotRun,
				[]*Test{&BFailed},
				"",
				Implemented,
				Common,
			},
			false,
			ResultDependencyFailed,
		},
		{
			"Dependency not run",
			fields{
				"Test A, runs dependency Test B",
				true,
				func(a hwapi.APIInterfaces, c *tools.Configuration) (bool, error, error) {
					return BNotRun.Result == ResultPass, nil, nil
				},
				ResultNotRun,
				[]*Test{&BNotRun},
				"",
				Implemented,
				Common,
			},
			true,
			ResultPass,
		},
		{
			"Multiple dependencies",
			fields{
				"Test A, multiple dependencies",
				true,
				func(a hwapi.APIInterfaces, c *tools.Configuration) (bool, error, error) {
					return BNotRun.Result == ResultPass, nil, nil
				},
				ResultNotRun,
				[]*Test{&BNotRun, &BNotImplemented},
				"",
				Implemented,
				Common,
			},
			true,
			ResultPass,
		},
		{
			"Internal error",
			fields{
				"Test A, returns internal error",
				true,
				func(a hwapi.APIInterfaces, c *tools.Configuration) (bool, error, error) {
					return true, nil, fmt.Errorf("Internal error 24")
				},
				ResultNotRun,
				[]*Test{},
				"",
				Implemented,
				Common,
			},
			false,
			ResultInternalError,
		},
		{
			"Regular test error",
			fields{
				"Test A, returns error",
				true,
				func(a hwapi.APIInterfaces, c *tools.Configuration) (bool, error, error) {
					return true, fmt.Errorf("error 1"), nil
				},
				ResultNotRun,
				[]*Test{},
				"",
				Implemented,
				Common,
			},
			false,
			ResultFail,
		},
		{
			"Regular test error critical",
			fields{
				"Test A, returns error, but is critical",
				true,
				func(a hwapi.APIInterfaces, c *tools.Configuration) (bool, error, error) {
					return false, fmt.Errorf("error 1"), nil
				},
				ResultNotRun,
				[]*Test{},
				"",
				Implemented,
				Common,
			},
			false,
			ResultFail,
		},
	}

	txtAPI := hwapi.GetAPI()
	var config tools.Configuration
	config.LCPHash = tpm2.AlgSHA256
	config.TPM = hwapi.TPMVersion20
	config.TXTMode = tools.AutoPromotion
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
				Spec:         tt.fields.Spec,
			}
			if got := tr.Run(txtAPI, &config); got != tt.wantReturn {
				t.Errorf("Test.Run() = %v, want %v", got, tt.wantReturn)
			}
			if tr.Result != tt.wantResult {
				t.Errorf("Test.Result = %v, want %v", tr.Result, tt.wantResult)
			}
		})
	}
}
