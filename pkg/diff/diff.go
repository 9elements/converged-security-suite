package diff

import (
	"bytes"
	"fmt"

	"github.com/9elements/converged-security-suite/v2/pkg/bootflow/systemartifacts/biosimage"
	"github.com/9elements/converged-security-suite/v2/pkg/bootflow/types"
	pkgbytes "github.com/linuxboot/fiano/pkg/bytes"
)

type Range = pkgbytes.Range
type Ranges = pkgbytes.Ranges

// Diff compares firmwareGoodData and firmwareBadData in areas specified by
// rangesOrig and returns the (memory) ranges where the data differs.
//
// ignoreByteSet is a set of bytes, each of which is just skipped while looking
// for differences.
func Diff(
	memRanges pkgbytes.Ranges,
	memMapper types.AddressMapper,
	firmwareGood, firmwareBad *biosimage.BIOSImage,
	ignoreByteSet []byte,
) (Ranges, error) {
	var diffEntries Ranges

	ranges := make(pkgbytes.Ranges, len(memRanges))
	copy(ranges, memRanges)
	ranges.SortAndMerge()

	rangesGood, err := memMapper.Resolve(firmwareGood, ranges...)
	if err != nil {
		return nil, fmt.Errorf("unable to resolve the good image ranges: %w", err)
	}

	if len(ranges) != len(rangesGood) {
		return nil, fmt.Errorf("currently Diff only one-to-one range mapping, but %d != %d", len(ranges), len(rangesGood))
	}

	rangesBad, err := memMapper.Resolve(firmwareBad, ranges...)
	if err != nil {
		return nil, fmt.Errorf("unable to resolve the bad image ranges: %w", err)
	}

	if len(rangesGood) != len(rangesBad) {
		return nil, fmt.Errorf("currently Diff only supports the case where the amount of ranges for both images are the same, but %d != %d", len(rangesGood), len(rangesBad))
	}

	firmwareGoodData, firmwareBadData := firmwareGood.Content, firmwareBad.Content

	for idx := range rangesGood {
		rM := ranges[idx]
		rG := rangesGood[idx]
		rB := rangesBad[idx]
		if rG.Length != rB.Length {
			return nil, fmt.Errorf("currently Diff only supports the case where the ranges between images has the same length, but %d != %d", rG.Length, rB.Length)
		}
		isCurrentlyMatch := true
		rGData := firmwareGoodData[rG.Offset : rG.Offset+rG.Length]
		rBData := firmwareBadData[rB.Offset : rB.Offset+rB.Length]
		prevOffsetM := uint64(0)
		for idx := range rGData {
			if bytes.IndexByte(ignoreByteSet, rGData[idx]) != -1 ||
				bytes.IndexByte(ignoreByteSet, rBData[idx]) != -1 {
				continue
			}
			newIsCurrentlyMatch := rGData[idx] == rBData[idx]
			if newIsCurrentlyMatch == isCurrentlyMatch {
				continue
			}
			offsetM := rM.Offset + uint64(idx)
			if !isCurrentlyMatch {
				// The block with difference has ended, adding it:
				diffEntries = append(diffEntries,
					pkgbytes.Range{
						Offset: prevOffsetM,
						Length: offsetM - prevOffsetM,
					},
				)
			}

			isCurrentlyMatch = newIsCurrentlyMatch
			prevOffsetM = offsetM
		}

		if !isCurrentlyMatch {
			diffEntries = append(diffEntries,
				pkgbytes.Range{
					Offset: prevOffsetM,
					Length: rM.Length + rM.Offset - prevOffsetM,
				},
			)
		}
	}

	return diffEntries, nil
}
