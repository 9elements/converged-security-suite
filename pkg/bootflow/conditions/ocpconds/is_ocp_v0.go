package ocpconds

import (
	"bytes"
	"context"
	"encoding/hex"

	"github.com/9elements/converged-security-suite/v2/pkg/bootflow/systemartifacts/biosimage"
	"github.com/9elements/converged-security-suite/v2/pkg/bootflow/types"
	ffsConsts "github.com/9elements/converged-security-suite/v2/pkg/uefi/ffs/consts"
)

func unhex(in string) []byte {
	out, err := hex.DecodeString(in)
	if err != nil {
		panic(err)
	}
	return out
}

var (
	ocpVendorVersionV0 = unhex("1EFB6B540C1D5540A4AD4EF4BF17B83A")
)

// IsOCPv0 checks if it is an OCP firmware of variant before 2022.
type IsOCPv0 struct{}

var _ types.Condition = (*IsOCPv0)(nil)

// Check implements types.Condition.
func (IsOCPv0) Check(_ context.Context, s *types.State) bool {
	biosImg, err := biosimage.Get(s)
	if err != nil {
		return false
	}

	uefi, err := biosImg.Parse()
	if err != nil {
		return false
	}

	sourceGUID := ffsConsts.GUIDAmiTcgPlatformPeiAfterMem
	nodes, err := uefi.GetByGUID(sourceGUID)
	if err != nil {
		return false
	}
	if len(nodes) == 0 {
		return false
	}
	if len(nodes) > 1 {
		return false
	}
	amiTcg := nodes[0]
	v := &visitorFindPE32{}
	if err := amiTcg.Apply(v); err != nil || v.Found == nil {
		return false
	}

	// TODO: do better/more_reliable signature check
	return bytes.Contains(v.Found.Buf(), ocpVendorVersionV0[len(ocpVendorVersionV0)-4:])
}

// FirmwareVendorVersion returns the well-known PCD Firmware Vendor Version string.
func (IsOCPv0) FirmwareVendorVersion() []byte {
	r := make([]byte, len(ocpVendorVersionV0))
	copy(r, ocpVendorVersionV0)
	return r
}
