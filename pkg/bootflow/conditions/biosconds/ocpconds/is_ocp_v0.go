package ocpconds

import (
	"bytes"
	"context"
	"encoding/hex"

	"github.com/9elements/converged-security-suite/v2/pkg/bootflow/systemartifacts/biosimage"
	"github.com/9elements/converged-security-suite/v2/pkg/bootflow/types"
	ffsConsts "github.com/9elements/converged-security-suite/v2/pkg/uefi/ffs/consts"
	"github.com/facebookincubator/go-belt/tool/logger"
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
func (IsOCPv0) Check(ctx context.Context, s *types.State) bool {
	biosImg, err := biosimage.Get(s)
	if err != nil {
		logger.Tracef(ctx, "unable to get BIOS image: %v", err)
		return false
	}

	uefi, err := biosImg.Parse()
	if err != nil {
		logger.Tracef(ctx, "unable to parse BIOS image: %v", err)
		return false
	}

	sourceGUID := ffsConsts.GUIDAmiTcgPlatformPeiAfterMem
	nodes, err := uefi.GetByGUID(sourceGUID)
	if err != nil {
		logger.Tracef(ctx, "unable to find GUID '%s': %v", sourceGUID, err)
		return false
	}
	if len(nodes) == 0 {
		logger.Tracef(ctx, "found zero objects with GUID '%s'", sourceGUID)
		return false
	}
	if len(nodes) > 1 {
		logger.Tracef(ctx, "found too many objects with GUID '%s': expected:1, found:%d", sourceGUID, len(nodes))
		return false
	}
	amiTcg := nodes[0]
	v := &visitorFindPE32orTE{}
	if err := amiTcg.Apply(v); err != nil || v.Found == nil {
		logger.Tracef(ctx, "unable to find PE32 or TE in '%s': err:%v, found:%v", sourceGUID, err, v.Found)
		return false
	}

	// TODO: do better/more_reliable signature check
	foundMagic := bytes.Contains(v.Found.Buf(), ocpVendorVersionV0[:4])
	if !foundMagic {
		foundMagic = bytes.Contains(v.Found.Buf(), ocpVendorVersionV0[len(ocpVendorVersionV0)-4:])
	}
	logger.Tracef(ctx, "is_found_magic:%v", foundMagic)
	return foundMagic
}

// FirmwareVendorVersion returns the well-known PCD Firmware Vendor Version string.
func (IsOCPv0) FirmwareVendorVersion() types.RawBytes {
	r := make([]byte, len(ocpVendorVersionV0))
	copy(r, ocpVendorVersionV0)
	return r
}
