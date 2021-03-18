package ffs

import (
	fianoGUID "github.com/linuxboot/fiano/pkg/guid"
	fianoUEFI "github.com/linuxboot/fiano/pkg/uefi"

	pkgbytes "github.com/9elements/converged-security-suite/v2/pkg/bytes"
)

type Node struct {
	fianoUEFI.Firmware
	pkgbytes.Range
}

func (node Node) GUID() *fianoGUID.GUID {
	switch f := node.Firmware.(type) {
	case *fianoUEFI.File:
		return &f.Header.GUID
	case *fianoUEFI.FirmwareVolume:
		return &f.FVName
	}
	return nil
}

// ModuleName returns the module name. In TianoCore it's called "BASE_NAME".
//
// Returns nil if this node has no module name.
func (node Node) ModuleName() *string {
	file, ok := node.Firmware.(*fianoUEFI.File)
	if !ok {
		return nil
	}

	for _, section := range file.Sections {
		switch section.Type {
		case "EFI_SECTION_USER_INTERFACE":
			return &[]string{section.String()}[0]
		case "EFI_SECTION_GUID_DEFINED":
			// If the module is compressed, then EFI_SECTION_USER_INTERFACE
			// is stored inside EFI_SECTION_GUID_DEFINED.
			for _, encapsulated := range section.Encapsulated {
				switch f := encapsulated.Value.(type) {
				case *fianoUEFI.Section:
					if f.Type == "EFI_SECTION_USER_INTERFACE" {
						return &[]string{f.String()}[0]
					}
				}
			}
		}
	}

	return nil
}
