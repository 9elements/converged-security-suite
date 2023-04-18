package ocpconds

import (
	"bytes"
	"context"

	"github.com/9elements/converged-security-suite/v2/pkg/bootflow/systemartifacts/biosimage"
	"github.com/9elements/converged-security-suite/v2/pkg/bootflow/types"
	ffsConsts "github.com/9elements/converged-security-suite/v2/pkg/uefi/ffs/consts"
	"github.com/facebookincubator/go-belt/tool/logger"
)

var (
	ocpVendorVersionV1 = unhex("052B10A7C7D9654181402ADDE94AF63C")
)

// IsOCPv0 checks if it is an OCP firmware of variant after 2022.
type IsOCPv1 struct{}

var _ types.Condition = (*IsOCPv1)(nil)

// Check implements types.Condition.
func (IsOCPv1) Check(ctx context.Context, s *types.State) bool {
	biosImg, err := biosimage.Get(s)
	if err != nil {
		logger.FromCtx(ctx).Tracef("unable to get BIOS image: %v", err)
		return false
	}

	uefi, err := biosImg.Parse()
	if err != nil {
		logger.FromCtx(ctx).Tracef("unable to parse BIOS image: %v", err)
		return false
	}

	sourceGUID := ffsConsts.GUIDAmiTpm20PlatformPei
	nodes, err := uefi.GetByGUID(sourceGUID)
	if err != nil {
		logger.FromCtx(ctx).Tracef("unable to find GUID '%s': %v", sourceGUID, err)
		return false
	}
	if len(nodes) == 0 {
		logger.FromCtx(ctx).Tracef("found zero objects with GUID '%s'", sourceGUID)
		return false
	}
	if len(nodes) > 1 {
		logger.FromCtx(ctx).Tracef("found too many objects with GUID '%s': expected:1, found:%d", sourceGUID, len(nodes))
		return false
	}

	amiTPM20 := nodes[0]
	v := &visitorFindPE32orTE{}
	if err := amiTPM20.ApplyChildren(v); err != nil || v.Found == nil {
		logger.FromCtx(ctx).Tracef("unable to find PE32 or TE in '%s': err:%v, found:%v", sourceGUID, err, v.Found)
		return false
	}

	// TODO: do better/more_reliable signature check
	foundMagic := bytes.Contains(v.Found.Buf(), ocpVendorVersionV1[:4])
	if !foundMagic {
		foundMagic = bytes.Contains(v.Found.Buf(), ocpVendorVersionV1[len(ocpVendorVersionV1)-4:])
	}
	logger.FromCtx(ctx).Tracef("is_found_magic:%v", foundMagic)
	return foundMagic
}

// FirmwareVendorVersion returns the well-known PCD Firmware Vendor Version string.
func (IsOCPv1) FirmwareVendorVersion() []byte {
	r := make([]byte, len(ocpVendorVersionV1))
	copy(r, ocpVendorVersionV1)
	return r
}
