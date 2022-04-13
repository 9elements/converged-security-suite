package tpm

import (
	"bytes"
	"crypto/sha1"
	"fmt"
	"strings"
)

const tpm12PCRsPath = `/sys/class/tpm/tpm0/pcrs`

const amountOfPCRs = 24

func parseSysfsPCRs(data []byte) ([amountOfPCRs][]byte, error) {
	var pcrs [amountOfPCRs][]byte
	// See a sample in the unit-test.

	for lineNum, line := range bytes.Split(data, []byte("\n")) {
		if len(line) == 0 {
			continue
		}
		var pcrIndex int
		var pcrValue []byte
		_, err := fmt.Sscanf(strings.ReplaceAll(string(line), " ", ""), "PCR-%02d:%X", &pcrIndex, &pcrValue)
		if err != nil {
			return pcrs, fmt.Errorf("unable to scan line '%s': %w", line, err)
		}
		if lineNum != pcrIndex {
			return pcrs, fmt.Errorf("unexpected PCRs order: expected:%d, received:%d", lineNum, pcrIndex)
		}
		if len(pcrValue) != sha1.Size {
			return pcrs, fmt.Errorf("expected SHA1 with length: 20 bytes, but received length %d: 0x%X (raw value: '%s')", len(pcrValue), pcrValue, line)
		}
		pcrs[pcrIndex] = pcrValue
	}

	return pcrs, nil
}
