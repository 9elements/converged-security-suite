package tools

import (
	"fmt"

	"github.com/linuxboot/fiano/pkg/uefi"
)

// CalcImageOffset returns the offset of a given uefi flash image
func CalcImageOffset(image []byte, addr uint64) (uint64, error) {
	off, size, err := getBIOSRegion(image)
	if err != nil {
		return 0, err
	}
	return uint64(off+size) - FourGiB + addr, nil
}

func getBIOSRegion(image []byte) (uint32, uint32, error) {
	if _, err := uefi.FindSignature(image); err != nil {
		return 0, 0, err
	}
	flash, err := uefi.NewFlashImage(image)
	if err != nil {
		return 0, 0, err
	}
	if flash.IFD.Region.FlashRegions[uefi.RegionTypeBIOS].Valid() {
		offset := flash.IFD.Region.FlashRegions[uefi.RegionTypeBIOS].BaseOffset()
		size := flash.IFD.Region.FlashRegions[uefi.RegionTypeBIOS].EndOffset() - offset
		return offset, size, nil
	}
	return 0, 0, fmt.Errorf("Couldn't find BIOS region")
}
