package pcr

import (
	"fmt"

	"github.com/9elements/converged-security-suite/v2/pkg/tpmeventlog"
)

// ErrUnknownPCRID means we don't know how to perform the requested action
// for the selected PCR register.
type ErrUnknownPCRID struct {
	PCRID ID
}

func (err *ErrUnknownPCRID) Error() string {
	return fmt.Sprintf("logic for %s is not implemented (yet?)",
		err.PCRID.String())
}

// ErrNoTXTPolicyRecord means there wasn't found any TXT Policy Record
// entries in the FIT.
type ErrNoTXTPolicyRecord struct{}

func (err *ErrNoTXTPolicyRecord) Error() string {
	return fmt.Sprintf("no TXT policy record")
}

// ErrCollect means it wasn't able to parse the construct PCR0_DATA structure.
type ErrCollect struct {
	MeasurementID MeasurementID
	Err           error
}

func (err ErrCollect) Error() string {
	return fmt.Sprintf("unable to collect measurement '%s': %v", err.MeasurementID, err.Err)
}

func (err ErrCollect) Unwrap() error {
	return err.Err
}

// ErrGetFIT means it wasn't able to parse the FIT table.
type ErrGetFIT struct {
	Err error
}

func (err ErrGetFIT) Error() string {
	return fmt.Sprintf("unable to parse FIT entries: %v", err.Err)
}

func (err ErrGetFIT) Unwrap() error {
	return err.Err
}

// ErrPCDVendorVersion means it was unable to detect PCD Vendor Version.
type ErrPCDVendorVersion struct{}

func (err ErrPCDVendorVersion) Error() string {
	return fmt.Sprintf("unable to find the source of firmware vendor version")
}

// ErrNotSupportedIndex means selected PCR index is not supported (yet?)
type ErrNotSupportedIndex struct {
	Index ID
}

// Error implements interface `error`.
func (err ErrNotSupportedIndex) Error() string {
	return fmt.Sprintf("PCR index %d is not supported", err.Index)
}

// ErrUnexpectedEventType means there was received an unexpected event type
type ErrUnexpectedEventType struct {
	Event  tpmeventlog.Event
	Reason string
}

// Error implements interface `error`.
func (err ErrUnexpectedEventType) Error() string {
	return fmt.Sprintf("unexpected event type, reason: '%s'; event: '%#+v'", err.Reason, err.Event)
}
