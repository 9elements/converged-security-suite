package tools

import (
	"fmt"

	"github.com/linuxboot/fiano/pkg/uefi"
)

// CalcImageOffset returns the offset of a given uefi flash image
func CalcImageOffset(image []byte, addr uint64) (uint64, error) {
	off, size, err := GetRegion(image, uefi.RegionTypeBIOS)
	if err != nil {
		return 0, err
	}
	return uint64(off+size) - FourGiB + addr, nil
}

// GetRegion returns offset and size of the given region type.
func GetRegion(image []byte, regionType uefi.FlashRegionType) (uint32, uint32, error) {
	if _, err := uefi.FindSignature(image); err != nil {
		return 0, 0, err
	}
	flash, err := uefi.NewFlashImage(image)
	if err != nil {
		return 0, 0, err
	}
	if flash.IFD.Region.FlashRegions[regionType].Valid() {
		offset := flash.IFD.Region.FlashRegions[regionType].BaseOffset()
		size := flash.IFD.Region.FlashRegions[regionType].EndOffset() - offset
		return offset, size, nil
	}
	return 0, 0, fmt.Errorf("Couldn't find region %d", regionType)
}
