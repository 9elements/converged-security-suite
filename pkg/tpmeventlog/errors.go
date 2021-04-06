package tpmeventlog

import (
	"fmt"
)

// ErrRead means unable to read from the io.Reader
type ErrRead struct {
	Err error
}

// Error implements interface `error`.
func (err ErrRead) Error() string {
	return fmt.Sprintf("unable to read the reader: %v", err.Err)
}

// Unwrap implements `xerrors.Wrapper`.
func (err ErrRead) Unwrap() error {
	return err.Err
}

// ErrParse means unable to read from the io.Reader
type ErrParse struct {
	Err error
}

// Error implements interface `error`.
func (err ErrParse) Error() string {
	return fmt.Sprintf("unable to parse the EventLog: %v", err.Err)
}

// Unwrap implements `xerrors.Wrapper`.
func (err ErrParse) Unwrap() error {
	return err.Err
}

// ErrLocality means it was unable to detect the locality to initialize
// the PCR0 value.
type ErrLocality struct {
	EventData []byte
}

// Error implements interface `error`.
func (err ErrLocality) Error() string {
	return fmt.Sprintf("unable to detect locality by event data '%x'", err.EventData)
}

// ErrInvalidDigestLength means an event has a digest of a size not appropriate
// for a selected hash algorithm.
type ErrInvalidDigestLength struct {
	Expected int
	Received int
}

// Error implements interface `error`.
func (err ErrInvalidDigestLength) Error() string {
	return fmt.Sprintf("invalid digest length, expected:%d, received:%d", err.Expected, err.Received)
}

// ErrNotSupportedHashAlgo means selected hash algorithm is not supported (yet?)
type ErrNotSupportedHashAlgo struct {
	TPMAlgo TPMAlgorithm
}

// Error implements interface `error`.
func (err ErrNotSupportedHashAlgo) Error() string {
	return fmt.Sprintf("not supported hash algorithm: 0x%x", err.TPMAlgo)
}
