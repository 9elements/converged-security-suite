package test

import (
	"fmt"
	"io"

	"github.com/9elements/converged-security-suite/v2/pkg/uefi/consts"
	"github.com/9elements/go-linux-lowlevel-hw/pkg/hwapi"
)

var _ io.ReadSeeker = (*txtAPIFirmwareReadSeeker)(nil)

type txtAPIFirmwareReadSeeker struct {
	TXTAPI          hwapi.LowLevelHardwareInterfaces
	CurrentPosition uint64
}

func newTXTAPIFirmwareReadSeeker(txtAPI hwapi.LowLevelHardwareInterfaces) *txtAPIFirmwareReadSeeker {
	return &txtAPIFirmwareReadSeeker{TXTAPI: txtAPI}
}

func (r *txtAPIFirmwareReadSeeker) Read(b []byte) (int, error) {
	err := r.TXTAPI.ReadPhysBuf(int64(r.CurrentPosition), b)
	if err != nil {
		return 0, err
	}

	r.CurrentPosition += uint64(len(b))
	return len(b), nil
}

func (r *txtAPIFirmwareReadSeeker) Seek(offset int64, whence int) (int64, error) {
	resultingOffset := int64(r.CurrentPosition)
	switch whence {
	case io.SeekStart:
		resultingOffset = offset
	case io.SeekCurrent:
		resultingOffset += offset
	case io.SeekEnd:
		resultingOffset = consts.BasePhysAddr + offset
	}
	if resultingOffset < 0 {
		return -1, fmt.Errorf("negative resulting offset %d on Seek with arguments: %d %v", resultingOffset, offset, whence)
	}
	if resultingOffset >= consts.BasePhysAddr {
		return -1, fmt.Errorf("resulting offset %d is higher than 4GiB on Seek with arguments: %d %v", resultingOffset, offset, whence)
	}

	r.CurrentPosition = uint64(resultingOffset)
	return resultingOffset, nil
}
