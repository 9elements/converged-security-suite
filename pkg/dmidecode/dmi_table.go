package dmidecode

import (
	"bytes"
	"fmt"
	"io"

	"github.com/9elements/converged-security-suite/v2/pkg/uefi"
	"github.com/digitalocean/go-smbios/smbios"
	"github.com/linuxboot/fiano/pkg/guid"
	fianoUEFI "github.com/linuxboot/fiano/pkg/uefi"
	"github.com/xaionaro-facebook/go-dmidecode"
)

// DMITable is a parsed DMI table.
type DMITable struct {
	*dmidecode.DMITable
}

// LocalDMITable returns the local DMI table (on Linux it is parsed from
// `sysfs`) .
func LocalDMITable() (*DMITable, error) {
	dmit, err := dmidecode.NewDMITable()
	if err != nil {
		return nil, err
	}
	return &DMITable{DMITable: dmit}, nil
}

// DMITableFromSMBIOSData returns a parsed instance on DMI table based only on
// SMBIOS data passes as `smbiosReader` argument.
func DMITableFromSMBIOSData(smbiosReader io.Reader) (*DMITable, error) {
	d := smbios.NewDecoder(smbiosReader)
	ss, err := d.Decode()
	if err != nil {
		return nil, dmidecode.ErrDecode{Err: err}
	}
	return &DMITable{
		DMITable: &dmidecode.DMITable{
			SMBIOSStructs: ss,
		},
	}, nil
}

var (
	guidSMBiosStaticData = *guid.MustParse(`DAF4BF89-CE71-4917-B522-C89D32FBC59F`)
)

// DMITableFromFirmwareImage returns a DMI table parsed from the image.
func DMITableFromFirmwareImage(imageBytes []byte) (*DMITable, error) {
	// SMBIOS static data could be stored in a compressed section, thus
	// decompression is required
	fw, err := uefi.ParseUEFIFirmwareBytes(imageBytes)
	if err != nil {
		return nil, ErrParseFirmware{Err: err}
	}

	return DMITableFromFirmware(fw)
}

// DMITableFromFirmware returns a DMI table parsed from the image.
func DMITableFromFirmware(fw *uefi.UEFI) (*DMITable, error) {
	nodes, err := fw.GetByGUID(guidSMBiosStaticData)
	if err != nil {
		return nil, ErrFindSMBIOSInFirmware{Err: err}
	}
	for _, node := range nodes {
		file, ok := node.Firmware.(*fianoUEFI.File)
		if !ok {
			return nil, ErrUnexpectedNodeType{Obj: node.Firmware}
		}
		for _, section := range file.Sections {
			data := section.Buf()
			if len(section.Encapsulated) > 0 {
				data = section.Encapsulated[0].Value.Buf()
			}
			// Freeform header length is 0x14 bytes long, skipping the header.
			if len(data) < 0x14 {
				continue
			}
			smBiosData := data[0x14:]
			return DMITableFromSMBIOSData(bytes.NewReader(smBiosData))
		}
	}

	return nil, ErrFindSMBIOSInFirmware{Err: fmt.Errorf("no appropriate nodes found")}
}
