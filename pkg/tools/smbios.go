package tools

import (
	"errors"

	"github.com/digitalocean/go-smbios/smbios"
)

// SMBIOSGetVendor gets the vendor name from table 0
func SMBIOSGetVendor() (*string, error) {
	rc, _, err := smbios.Stream()
	if err != nil {
		return nil, err
	}
	defer rc.Close()
	d := smbios.NewDecoder(rc)
	ss, err := d.Decode()
	if err != nil {
		return nil, err
	}
	for _, s := range ss {
		if s.Header.Type == 0 {
			return &s.Strings[0], nil
		}
	}
	return nil, errors.New("Firmware vendor string in SMBIOS not found")
}
