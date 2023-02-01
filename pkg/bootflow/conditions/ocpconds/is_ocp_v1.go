package ocpconds

import (
	"bytes"
	"context"

	"github.com/9elements/converged-security-suite/v2/pkg/bootflow/systemartifacts/biosimage"
	"github.com/9elements/converged-security-suite/v2/pkg/bootflow/types"
	ffsConsts "github.com/9elements/converged-security-suite/v2/pkg/uefi/ffs/consts"
)

var (
	ocpVendorVersionV1 = unhex("052B10A7C7D9654181402ADDE94AF63C")
)

// IsOCPv0 checks if it is an OCP firmware of variant after 2022.
type IsOCPv1 struct{}

var _ types.Condition = (*IsOCPv1)(nil)

// Check implements types.Condition.
func (IsOCPv1) Check(_ context.Context, s *types.State) bool {
	biosImg, err := biosimage.Get(s)
	if err != nil {
		return false
	}

	uefi, err := biosImg.Parse()
	if err != nil {
		return false
	}

	sourceGUID := ffsConsts.GUIDAmiTpm20PlatformPei
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

	amiTPM20 := nodes[0]
	v := &visitorFindPE32{}
	if err := amiTPM20.ApplyChildren(v); err != nil || v.Found == nil {
		return false
	}

	// TODO: do better/more_reliable signature check
	return bytes.Contains(v.Found.Buf(), ocpVendorVersionV1[len(ocpVendorVersionV1)-4:])
}

// FirmwareVendorVersion returns the well-known PCD Firmware Vendor Version string.
func (IsOCPv1) FirmwareVendorVersion() []byte {
	r := make([]byte, len(ocpVendorVersionV1))
	copy(r, ocpVendorVersionV1)
	return r
}
