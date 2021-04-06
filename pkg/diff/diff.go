package diff

import (
	"bytes"
	_ "net/http/pprof"

	pkgbytes "github.com/9elements/converged-security-suite/v2/pkg/bytes"
)

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
