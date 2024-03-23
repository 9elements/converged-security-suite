package format

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/9elements/converged-security-suite/v2/pkg/bootflow/systemartifacts/biosimage"
	"github.com/9elements/converged-security-suite/v2/pkg/bootflow/types"
	"github.com/9elements/converged-security-suite/v2/pkg/diff"
	pkgbytes "github.com/linuxboot/fiano/pkg/bytes"
)

const (
	// rangeSizeThreshold defines the threshold to do not print details
	// for a range size.
	rangeSizeThreshold = 100

	// rangesThreshold defines the threshold to do not print details
	// for amount of ranges (that differs) in a diff report.
	rangesThreshold = 20

	// non00orFFOutputHammingDistanceThreshold defines the threshold to
	// do not print details for ranges with non-zero non-00-or-ff hamming
	// distance if threshold rangesThreshold was exceeded.
	//
	// "non-00-or-ff hamming distance" is the hamming distance excluding
	// those bytes where "bad" image's byte is 0x00 or 0xff.
	non00orFFOutputHammingDistanceThreshold = 1000

	// printWordByteLength defines the length of a line of a hexdump
	// (how many bytes are printed in one line).
	printWordByteLength = 8
)

// AsText formats a report as a text for a CLI.
func AsText(
	report diff.AnalysisReport,
	debugInfo map[string]interface{},
	goodData, badData *biosimage.BIOSImage,
) (string, error) {
	var result strings.Builder

	debugInfoBytes, err := json.MarshalIndent(debugInfo, "", "  ")
	if err != nil {
		return "", fmt.Errorf("unable to JSONize debugInfo: %w", err)
	}
	result.WriteString(fmt.Sprintln("debugInfo:", string(debugInfoBytes)))

	if len(report.Entries) < rangesThreshold {
		for _, entry := range report.Entries {
			result.WriteString(fmt.Sprintf("\noffset: 0x%x; bytes differs: %d; hamming distance is: %d, "+
				"for non-(0x00|0xff): %d.\n",
				entry.DiffRange.Offset, entry.DiffRange.Length, entry.HammingDistance, entry.HammingDistanceNon00orFF))
			if len(entry.RelatedMeasurements) > 0 {
				result.WriteString(fmt.Sprintf("related measurements: %v\n", diff.RelatedMeasurementsLaconic(entry.RelatedMeasurements)))
			}
			if len(entry.Nodes) > 0 {
				result.WriteString(fmt.Sprintf("related nodes: %v\n", entry.Nodes))
			}

			if entry.DiffRange.Length >= rangeSizeThreshold {
				continue
			}

			entryInHex, err := dumpDiffEntryInHex(entry.DiffRange, report.AddressMapper, goodData, badData)
			if err != nil {
				return "", fmt.Errorf("unable to dump into hex a range: %w", err)
			}
			result.WriteString(entryInHex)
		}
	}

	result.WriteString("\nTotal:\n")
	result.WriteString(fmt.Sprintf("\tchanged bytes: %d (in %d ranges)\n", report.BytesChanged, len(report.Entries)))
	result.WriteString(fmt.Sprintf("\thamming distance: %d\n", report.HammingDistance))
	result.WriteString(fmt.Sprintf("\thamming distance for non-(0x00|0xff) bytes: %d\n", report.HammingDistanceNon00orFF))
	result.WriteString(fmt.Sprintf("The earliest offset of a different measured byte: 0x%X\n", report.FirstProblemOffset))

	earliestRangeG, earliestRangeB, err := resolveRange(pkgbytes.Range{
		Offset: report.FirstProblemOffset,
		Length: 1,
	}, report.AddressMapper, goodData, badData)
	if err != nil {
		return "", fmt.Errorf("unable to resolve the earliest range: %w", err)
	}
	if earliestRangeB.Offset != earliestRangeG.Offset {
		result.WriteString(fmt.Sprintf("The earliest offset of a different measured byte in good image: 0x%08X\n", earliestRangeG.Offset))
		result.WriteString(fmt.Sprintf("The earliest offset of a different measured byte in  bad image: 0x%08X\n", earliestRangeB.Offset))
	} else {
		result.WriteString(fmt.Sprintf("The earliest offset of a different measured byte in the image: 0x%08X\n", earliestRangeG.Offset))
	}

	// If we did not print dumps, but totalHammingDistanceNon00orFF is not that large
	// than we can dump the difference causes this totalHammingDistanceNon00orFF.
	if len(report.Entries) < rangesThreshold ||
		report.HammingDistanceNon00orFF == 0 && report.HammingDistanceNon00orFF > non00orFFOutputHammingDistanceThreshold {
		return result.String(), nil
	}

	result.WriteString("\nSome non-(0x00|0xff)-related diffs:\n")

	for _, entry := range report.Entries {
		if entry.DiffRange.Length >= rangeSizeThreshold {
			continue
		}
		if entry.HammingDistanceNon00orFF == 0 {
			continue
		}

		result.WriteString(fmt.Sprintf("\noffset: 0x%x; bytes differs: %d; non-(0x00|0xff) hamming distance: %d.\n",
			entry.DiffRange.Offset, entry.DiffRange.Length, entry.HammingDistanceNon00orFF))
		if len(entry.RelatedMeasurements) > 0 {
			result.WriteString(fmt.Sprintf("related measurements: %v\n", diff.RelatedMeasurementsLaconic(entry.RelatedMeasurements)))
		}
		if len(entry.Nodes) > 0 {
			result.WriteString(fmt.Sprintf("related nodes: %v\n", entry.Nodes))
		}

		entryInHex, err := dumpDiffEntryInHex(entry.DiffRange, report.AddressMapper, goodData, badData)
		if err != nil {
			return "", fmt.Errorf("unable to dump into hex a range: %w", err)
		}
		result.WriteString(entryInHex)
	}

	return result.String(), nil
}

func resolveRange(
	memRange pkgbytes.Range,
	memMapper types.AddressMapper,
	goodData, badData *biosimage.BIOSImage,
) (pkgbytes.Range, pkgbytes.Range, error) {
	rangesG, err := memMapper.Resolve(goodData, memRange)
	if err != nil {
		return pkgbytes.Range{}, pkgbytes.Range{}, fmt.Errorf("unable to resolve the good data: %w", err)
	}
	if len(rangesG) != 1 {
		return pkgbytes.Range{}, pkgbytes.Range{}, fmt.Errorf("not supported, yet; we currently support only 1-to-1 mapping of ranges: %d", len(rangesG))
	}
	rangeG := rangesG[0]
	rangesB, err := memMapper.Resolve(goodData, memRange)
	if err != nil {
		return pkgbytes.Range{}, pkgbytes.Range{}, fmt.Errorf("unable to resolve the bad data: %w", err)
	}
	if len(rangesB) != 1 {
		return pkgbytes.Range{}, pkgbytes.Range{}, fmt.Errorf("not supported, yet; we currently support only 1-to-1 mapping of ranges: %d", len(rangesB))
	}
	rangeB := rangesB[0]

	return rangeG, rangeB, nil
}

func dumpDiffEntryInHex(
	diffRange pkgbytes.Range,
	memMapper types.AddressMapper,
	goodData, badData *biosimage.BIOSImage,
) (string, error) {
	var result strings.Builder

	// Get whole lines aligned by "printWordByteLength" bytes addresses.
	alignMask := ^uint64(printWordByteLength - 1)
	logStartOffset := diffRange.Offset & alignMask
	logEndOffset := (diffRange.Offset + diffRange.Length + ^alignMask) & (alignMask)

	// Add a line from top and bottom for better readability
	logStartOffset -= printWordByteLength
	logEndOffset += printWordByteLength

	// Resolve the offset into given files.
	logRangeG, logRangeB, err := resolveRange(pkgbytes.Range{
		Offset: logStartOffset,
		Length: logEndOffset,
	}, memMapper, goodData, badData)
	if err != nil {
		return "", err
	}

	// Dump the lines:
	for lineOffset := uint64(0); lineOffset < logEndOffset-logStartOffset; lineOffset += printWordByteLength {
		result.WriteString(fmt.Sprintf("0x%08X:  ", logStartOffset+lineOffset))
		for offset := lineOffset; offset < lineOffset+printWordByteLength; offset++ {
			result.WriteString(fmt.Sprintf(" %02X", goodData.Content[offset+logRangeG.Offset]))
			innerOffset := int64(logStartOffset+offset) - int64(diffRange.Offset)
			if innerOffset < 0 || uint64(innerOffset) >= diffRange.Length ||
				goodData.Content[offset+logRangeG.Offset] == badData.Content[offset+logRangeB.Offset] {
				result.WriteString("   ")
				continue
			}
			result.WriteString(fmt.Sprintf("|%02X", badData.Content[offset+logRangeB.Offset]))
		}
		result.WriteString("\n")
	}

	return result.String(), nil
}
