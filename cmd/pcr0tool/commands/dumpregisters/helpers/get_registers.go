package helpers

import (
	"fmt"
	"io/ioutil"
	"runtime"

	"github.com/9elements/converged-security-suite/v2/pkg/errors"
	"github.com/9elements/converged-security-suite/v2/pkg/registers"
	"github.com/9elements/go-linux-lowlevel-hw/pkg/hwapi"
)

type getRegistersConfig struct {
	LocalhostByDefault bool
	OverrideTXTPublic  string
}

// GetRegistersOption is an option for function GetRegisters
type GetRegistersOption interface {
	apply(*getRegistersConfig) error
}

// OptLocalhostByDefault an option to GetRegisters which signals to extract
// data from localhost if no other sources are provided.
type OptLocalhostByDefault bool

func (opt OptLocalhostByDefault) apply(cfg *getRegistersConfig) error {
	cfg.LocalhostByDefault = bool(opt)
	return nil
}

// OptTXTPublic an option to GetRegisters to provide a path to a file
// with TXT Public space dumped.
type OptTXTPublic string

func (opt OptTXTPublic) apply(cfg *getRegistersConfig) error {
	cfg.OverrideTXTPublic = string(opt)
	return nil
}

type getRegistersOptions []GetRegistersOption

// Config converts a bunch of options to a config.
func (opts getRegistersOptions) Config() (getRegistersConfig, error) {
	var cfg getRegistersConfig
	for _, opt := range opts {
		if err := opt.apply(&cfg); err != nil {
			return cfg, fmt.Errorf("unable to apply option %T:%v due to error: %w", opt, opt, err)
		}
	}
	return cfg, nil
}

// GetRegisters extracts status registers.
func GetRegisters(options ...GetRegistersOption) (registers.Registers, error) {
	cfg, err := getRegistersOptions(options).Config()
	if err != nil {
		return nil, fmt.Errorf("invalid arguments: %w", err)
	}
	if runtime.GOOS != "linux" {
		return nil, fmt.Errorf("command is supported only on Linux platform")
	}

	// TODO: add support for non-Intel systems
	txtConfig, err := getTXTConfig(cfg)
	if err != nil {
		return nil, fmt.Errorf("TXT public space is not provided: %w", err)
	}

	msrReader := &registers.DefaultMSRReader{}
	txtRegisters, txtErr := registers.ReadTXTRegisters(txtConfig)
	msrRegisters, msrErr := registers.ReadMSRRegisters(msrReader)
	allRegisters := append(txtRegisters, msrRegisters...)

	return allRegisters, (&errors.MultiError{}).Add(txtErr, msrErr).ReturnValue()
}

func getTXTConfig(cfg getRegistersConfig) (registers.TXTConfigSpace, error) {
	if cfg.OverrideTXTPublic != "" {
		b, err := ioutil.ReadFile(cfg.OverrideTXTPublic)
		if err != nil {
			return nil, fmt.Errorf("unable to read TXT public space from '%s': %w", cfg.OverrideTXTPublic, err)
		}
		return registers.TXTConfigSpace(b), nil
	}

	if !cfg.LocalhostByDefault {
		return nil, fmt.Errorf("no source defined for TXT status registers")
	}
	txtAPI := hwapi.GetAPI()
	txtConfig, err := registers.FetchTXTConfigSpaceSafe(txtAPI)
	if err != nil {
		return nil, fmt.Errorf("unable to fetch TXT public space: %w", err)
	}
	return txtConfig, nil
}
