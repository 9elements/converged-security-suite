package helpers

import (
	"bytes"

	"github.com/9elements/converged-security-suite/v2/pkg/pcd/consts"
)

// FindPEFileStart returns the index of the first occurance of "MZ" magic string.
//
// See: https://upload.wikimedia.org/wikipedia/commons/thumb/1/1b/Portable_Executable_32_bit_Structure_in_SVG_fixed.svg/1280px-Portable_Executable_32_bit_Structure_in_SVG_fixed.svg.png
func FindPEFileStart(data []byte) (result int) {
	end := len(data) - 0x125
	for result = 0; result < end; result++ {
		if !bytes.Equal(data[result:result+2], consts.MZSignature) {
			continue
		}

		return
	}

	return -1
}
