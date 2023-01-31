package ocpconds

import (
	"bytes"
	"encoding/hex"

	"github.com/9elements/converged-security-suite/v2/pkg/bootflow/systemartifacts/biosimage"
	"github.com/9elements/converged-security-suite/v2/pkg/bootflow/types"
	"github.com/9elements/converged-security-suite/v2/pkg/pcd"
)

func unhex(in string) []byte {
	out, err := hex.DecodeString(in)
	if err != nil {
		panic(err)
	}
	return out
}

var (
	ocpVendorVersion = unhex("1EFB6B540C1D5540A4AD4EF4BF17B83A")
)

type IsOCP struct{}

func (IsOCP) Check(s *types.State) bool {
	biosImg, err := biosimage.Get(s)
	if err != nil {
		return false
	}

	uefi, err := biosImg.Parse()
	if err != nil {
		return false
	}

	parsed, err := pcd.ParseFirmware(uefi)
	if err != nil {
		return false
	}

	return bytes.Equal(parsed.GetFirmwareVendorVersion(), ocpVendorVersion)
}
