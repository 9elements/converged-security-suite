package tools

import (
	"fmt"

	"github.com/linuxboot/fiano/pkg/uefi"

	"github.com/9elements/converged-security-suite/v2/pkg/uefi/consts"
)

// CalcImageOffset returns the offset of a given uefi flash image
func CalcImageOffset(image []byte, addr uint64) (uint64, error) {
	off, size, err := GetRegion(image, uefi.RegionTypeBIOS)
	if err != nil {
		return 0, err
	}
	return uint64(off+size) - consts.BasePhysAddr + addr, nil
}

// GetRegion returns offset and size of the given region type.
func GetRegion(image []byte, regionType uefi.FlashRegionType) (uint32, uint32, error) {
	defer suppressFianoLog()()

	if _, err := uefi.FindSignature(image); err != nil {
		return 0, 0, fmt.Errorf("count not find the signature: %w", err)
	}
	flash, err := uefi.NewFlashImage(image)
	if err != nil {
		return 0, 0, fmt.Errorf("count not initialize a flash image: %w", err)
	}
	if flash.IFD.Region.FlashRegions[regionType].Valid() {
		offset := flash.IFD.Region.FlashRegions[regionType].BaseOffset()
		size := flash.IFD.Region.FlashRegions[regionType].EndOffset() - offset
		return offset, size, nil
	}
	return 0, 0, fmt.Errorf("could not find region %d", regionType)
}
