package dmidecode

import (
	"fmt"
)

type ErrDMITable struct {
	Err error
}

func (err ErrDMITable) Error() string {
	return fmt.Sprintf("unable to get a DMI table: %v", err.Err)
}

func (err ErrDMITable) Unwrap() error {
	return err.Err
}

// ErrParseFirmware means a problem while parsing a firmware image.
type ErrParseFirmware struct {
	Err error
}

func (err ErrParseFirmware) Error() string {
	return fmt.Sprintf("unable to parse firmware: %v", err.Err)
}

func (err ErrParseFirmware) Unwrap() error {
	return err.Err
}

// ErrFindSMBIOSInFirmware means SMBIOS static data section was not found.
type ErrFindSMBIOSInFirmware struct {
	Err error
}

func (err ErrFindSMBIOSInFirmware) Error() string {
	return fmt.Sprintf("unable to find SMBIOS static data in the firmware: %v", err.Err)
}

func (err ErrFindSMBIOSInFirmware) Unwrap() error {
	return err.Err
}

// ErrUnexpectedNodeType means firmware has an unexpected node type.
type ErrUnexpectedNodeType struct {
	Obj interface{}
}

func (err ErrUnexpectedNodeType) Error() string {
	return fmt.Sprintf("unexpected node type: %T", err.Obj)
}
