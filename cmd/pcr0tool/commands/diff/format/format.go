package format

import (
	"encoding/json"
	"fmt"
	"strings"

	pkgbytes "github.com/9elements/converged-security-suite/v2/pkg/bytes"
	"github.com/9elements/converged-security-suite/v2/pkg/diff"
	"github.com/9elements/converged-security-suite/v2/pkg/pcr"
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
	measurements pcr.Measurements,
	goodData []byte,
	badData []byte,
) (output string, err error) {
	var result strings.Builder
	defer func() {
		output = result.String()
	}()

	debugInfoBytes, err := json.MarshalIndent(debugInfo, "", "  ")
	if err != nil {
		return "", fmt.Errorf("unable to JSONize debugInfo: %w", err)
	}
	result.WriteString(fmt.Sprintln("debugInfo:", string(debugInfoBytes)))

	for _, measurement := range measurements {
		result.WriteString(fmt.Sprintln(measurement))
	}

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

			result.WriteString(dumpDiffEntryInHex(entry.DiffRange, goodData, badData))
		}
	}

	result.WriteString(fmt.Sprintf("\nTotal:\n"))
	result.WriteString(fmt.Sprintf("\tchanged bytes: %d (in %d ranges)\n", report.BytesChanged, len(report.Entries)))
	result.WriteString(fmt.Sprintf("\thamming distance: %d\n", report.HammingDistance))
	result.WriteString(fmt.Sprintf("\thamming distance for non-(0x00|0xff) bytes: %d\n", report.HammingDistanceNon00orFF))
	result.WriteString(fmt.Sprintf("The earliest offset of a different measured bytes: 0x%x\n", report.FirstProblemOffset))

	// If we did not print dumps, but totalHammingDistanceNon00orFF is not that large
	// than we can dump the difference causes this totalHammingDistanceNon00orFF.
	if len(report.Entries) < rangesThreshold ||
		report.HammingDistanceNon00orFF == 0 && report.HammingDistanceNon00orFF > non00orFFOutputHammingDistanceThreshold {
		return
	}

	result.WriteString(fmt.Sprintf("\nSome non-(0x00|0xff)-related diffs:\n"))

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

		result.WriteString(dumpDiffEntryInHex(entry.DiffRange, goodData, badData))
	}

	return
}

func dumpDiffEntryInHex(
	diffRange pkgbytes.Range,
	goodData []byte,
	badData []byte,
) (output string) {
	var result strings.Builder
	defer func() {
		output = result.String()
	}()

	// Get whole lines aligned by "printWordByteLength" bytes addresses.
	alignMask := ^uint64(printWordByteLength - 1)
	logStartOffset := diffRange.Offset & alignMask
	logEndOffset := (diffRange.Offset + diffRange.Length + ^alignMask) & (alignMask)

	// Add a line from top and bottom for better readability
	logStartOffset -= printWordByteLength
	logEndOffset += printWordByteLength

	// Dump the lines:
	for lineOffset := logStartOffset; lineOffset < logEndOffset; lineOffset += printWordByteLength {
		result.WriteString(fmt.Sprintf("0x%016X:  ", lineOffset))
		for offset := lineOffset; offset < lineOffset+printWordByteLength; offset++ {
			result.WriteString(fmt.Sprintf(" %02X", goodData[offset]))
			innerOffset := int64(offset) - int64(diffRange.Offset)
			if innerOffset < 0 || uint64(innerOffset) >= diffRange.Length ||
				goodData[offset] == badData[offset] {
				result.WriteString(fmt.Sprintf("   "))
				continue
			}
			result.WriteString(fmt.Sprintf("|%02X", badData[offset]))
		}
		result.WriteString(fmt.Sprintf("\n"))
	}

	return
}
