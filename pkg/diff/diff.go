package diff

import (
	"bytes"

	pkgbytes "github.com/linuxboot/fiano/pkg/bytes"
)

// Diff compares firmwareGoodData and firmwareBadData in areas specified by
// rangesOrig and returns the ranges where the data differs.
//
// ignoreByteSet is a set of bytes, each of which is just skipped while looking
// for differences.
func Diff(rangesOrig pkgbytes.Ranges, firmwareGoodData, firmwareBadData, ignoreByteSet []byte) pkgbytes.Ranges {
	var diffEntries pkgbytes.Ranges

	ranges := make(pkgbytes.Ranges, len(rangesOrig))
	copy(ranges, rangesOrig)
	ranges.SortAndMerge()

	for _, _range := range ranges {
		isCurrentlyMatch := true
		rangeGoodData := firmwareGoodData[_range.Offset : _range.Offset+_range.Length]
		rangeBadData := firmwareBadData[_range.Offset : _range.Offset+_range.Length]
		prevOffset := uint64(0)
		for idx := range rangeGoodData {
			if bytes.IndexByte(ignoreByteSet, rangeGoodData[idx]) != -1 ||
				bytes.IndexByte(ignoreByteSet, rangeBadData[idx]) != -1 {
				continue
			}
			newIsCurrentlyMatch := rangeGoodData[idx] == rangeBadData[idx]
			if newIsCurrentlyMatch == isCurrentlyMatch {
				continue
			}
			offset := _range.Offset + uint64(idx)
			if !isCurrentlyMatch {
				// The block with difference has ended, adding it:
				diffEntries = append(diffEntries, pkgbytes.Range{
					Offset: prevOffset,
					Length: offset - prevOffset,
				})
			}

			isCurrentlyMatch = newIsCurrentlyMatch
			prevOffset = offset
		}

		if !isCurrentlyMatch {
			diffEntries = append(diffEntries, pkgbytes.Range{
				Offset: prevOffset,
				Length: uint64(len(rangeGoodData)) + _range.Offset - prevOffset,
			})
		}
	}

	return diffEntries
}
