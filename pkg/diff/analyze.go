package diff

import (
	"bytes"
	"fmt"
	"log"
	"math"
	_ "net/http/pprof"
	"strings"

	"github.com/golang-collections/go-datastructures/augmentedtree"
	"github.com/google/uuid"
	fianoUEFI "github.com/linuxboot/fiano/pkg/uefi"
	"github.com/steakknife/hamming"

	pkgbytes "github.com/9elements/converged-security-suite/v2/pkg/bytes"
	"github.com/9elements/converged-security-suite/v2/pkg/mathtools"
	"github.com/9elements/converged-security-suite/v2/pkg/pcr"
	"github.com/9elements/converged-security-suite/v2/pkg/uefi/ffs"
)

const (
	// rangeAmountThresholdReduceRanges defines the threshold when it is
	// required to try to merge ranges to reduce the calculation time.
	rangeAmountThresholdReduceRanges = 1000

	// reduceRangesDistance defines the maximal distance between ranges
	// to merge them.
	reduceRangesDistance = 1023
)

func hammingDistance(a, b []byte, excludeCharsA, excludeCharsB []byte) uint64 {
	l := mathtools.Min(len(a), len(b))
	a = a[:l]
	b = b[:l]

	if len(excludeCharsA) == 0 && len(excludeCharsB) == 0 {
		return uint64(hamming.Bytes(a, b))
	}

	var distance uint64
	for idx := range a {
		if bytes.IndexByte(excludeCharsA, a[idx]) != -1 || bytes.IndexByte(excludeCharsB, b[idx]) != -1 {
			continue
		}
		distance += uint64(hamming.Byte(a[idx], b[idx]))
	}
	return distance
}

// NodeInfo is a struct contains information about one UEFI FFS node.
type NodeInfo struct {
	UUID        uuid.UUID
	Description string
}

var emptyUUID uuid.UUID

func (nodeInfo NodeInfo) String() string {
	if nodeInfo.Description == "" && bytes.Compare(nodeInfo.UUID[:], emptyUUID[:]) == 0 {
		return "unknown"
	}
	if nodeInfo.Description != "" {
		return nodeInfo.Description
	}
	return nodeInfo.UUID.String()
}

// RelatedMeasurement contains the related measurement and the data chunks
// specifically related to the diff.
type RelatedMeasurement struct {
	RelatedDataChunks pcr.DataChunks
	pcr.Measurement
}

// RelatedMeasurementsLaconic is a helper to print measurements in a laconic way
type RelatedMeasurementsLaconic []RelatedMeasurement

func (s RelatedMeasurementsLaconic) String() string {
	var ids []string
	for _, measurement := range s {
		chunksComment := laconicChunksString(measurement.RelatedDataChunks)
		if chunksComment == "" {
			ids = append(ids, measurement.ID.String())
			continue
		}
		ids = append(ids, measurement.ID.String()+":"+chunksComment)
	}
	return strings.Join(ids, ", ")
}

func laconicChunksString(chunks pcr.DataChunks) string {
	var r []string
	for _, chunk := range chunks {
		if chunk.ID == pcr.DataChunkIDUndefined {
			// if at least one chunk has no comment, then we cannot construct
			// a valid string, let's signal about the problem through returning
			// an empty string.
			return ""
		}
		r = append(r, chunk.ID.String())
	}
	return strings.Join(r, ",")
}

// AnalysisReportEntry contains information about on block with different data.
type AnalysisReportEntry struct {
	// DiffRange is the information about offsets where the data is different.
	DiffRange pkgbytes.Range

	// HammingDistance is a bit-wise hamming distance between the data blocks.
	HammingDistance uint64

	// HammingDistanceNon00orFF is a bit-wise hamming distance between the data
	// blocks, excluding bytes 0x00 and 0xff
	HammingDistanceNon00orFF uint64

	// RelatedMeasurements contains the list of measurements which overlaps
	// with the data block.
	RelatedMeasurements []RelatedMeasurement

	// Nodes contains the list of UEFI nodes (regions, volumes, modules, files)
	// which overlaps with the data block
	Nodes []NodeInfo
}

// AnalysisReport contains an analyzed report for an UEFI image diff.
type AnalysisReport struct {
	// Entries contains each block with different data.
	Entries []AnalysisReportEntry

	// FirstProblemOffset is the offset of the first byte with a different value.
	FirstProblemOffset uint64

	// BytesChanged is a count of bytes with different values.
	BytesChanged uint64

	// HammingDistance is a bit-wise hamming distance between images.
	HammingDistance uint64

	// HammingDistanceNon00orFF is a bit-wise hamming distance between images, excluding
	// bytes 0x00 and 0xff
	HammingDistanceNon00orFF uint64
}

// Firmware is an abstraction over *uefi.UEFI
type Firmware interface {
	Buf() []byte
	GetByRange(byteRange pkgbytes.Range) (nodes []*ffs.Node, err error)
	NameToRangesMap() map[string]pkgbytes.Ranges
}

// Analyze generates a difference report filled with additional simple
// analytics, like hamming distance.
func Analyze(
	diffRangesOrig pkgbytes.Ranges,
	measurements pcr.Measurements,
	goodFirmware Firmware,
	badData []byte,
) (report AnalysisReport) {
	diffRangesOrig.Sort()
	diffRanges := pkgbytes.MergeRanges(diffRangesOrig, 0)

	if len(diffRanges) > rangeAmountThresholdReduceRanges {
		diffRanges = pkgbytes.MergeRanges(diffRanges, reduceRangesDistance)
	}

	goodData := goodFirmware.Buf()

	// Preparing data structures to quickly find UEFI nodes overlapping with
	// a byte range.

	allNodes, err := goodFirmware.GetByRange(pkgbytes.Range{
		Offset: 0,
		Length: uint64(len(goodData)),
	})
	if err != nil {
		log.Println("unable to scan for UEFI nodes:", err)
	}
	nodesIntervalTree := newNodesIntervalTree(allNodes)
	namesIntervalTree := newNamesIntervalTree(goodFirmware.NameToRangesMap())

	// Preparing a report

	report.FirstProblemOffset = math.MaxUint64
	for _, diffRange := range diffRanges {
		entryEndOffset := diffRange.Offset + diffRange.Length
		entryGoodData := goodData[diffRange.Offset:entryEndOffset]
		entryBadData := badData[diffRange.Offset:entryEndOffset]

		var relatedMeasurements []RelatedMeasurement
		for _, m := range measurements {
			var relatedDataChunks pcr.DataChunks
			for _, data := range m.Data {
				if data.Range.Intersect(diffRange) {
					relatedDataChunks = append(relatedDataChunks, *data.Copy())
				}
			}
			if len(relatedDataChunks) == 0 {
				continue
			}
			relatedMeasurements = append(relatedMeasurements, RelatedMeasurement{
				RelatedDataChunks: relatedDataChunks,
				Measurement:       *m.Copy(),
			})
		}

		// Filling some analysisEntry fields
		analysisEntry := AnalysisReportEntry{
			DiffRange:                diffRange,
			HammingDistance:          hammingDistance(entryGoodData, entryBadData, nil, nil),
			HammingDistanceNon00orFF: hammingDistance(entryGoodData, entryBadData, nil, []byte{0x00, 0xff}),
			RelatedMeasurements:      relatedMeasurements,
		}

		// Filling analysisEntry.Nodes
		//
		// analysisEntry.Nodes should contain a list of UEFI nodes (regions,
		// volumes, modules, files) which overlaps with the diffRange.
		var overlappedNodes []*ffs.Node
		for _, node := range nodesIntervalTree.FindOverlapping(diffRange) {
			overlappedNodes = append(overlappedNodes, node.(*ffs.Node))
		}
		if len(overlappedNodes) == 0 {
			// We use an ugly `unsafe` hack to extract bytes ranges,
			// because https://github.com/linuxboot/fiano/pull/317 is still
			// not fixed (and therefore not merged).
			//
			// And a bytes range is not always detected, so sometimes
			// nodesIntervalTree.FindOverlapping(diffRange) will return zero entries
			// even if the range is definitely related to some nodes. In this
			// case we use a fallback way, which is more reliable, but returns
			// only names (instead of *ffs.Node objects).
			for _, name := range namesIntervalTree.FindOverlapping(diffRange) {
				analysisEntry.Nodes = append(analysisEntry.Nodes, NodeInfo{
					Description: name.(string),
				})
			}
		} else {
			analysisEntry.Nodes = nodesInfo(overlappedNodes)
		}

		// Filling report

		if diffRange.Offset < report.FirstProblemOffset {
			report.FirstProblemOffset = diffRange.Offset
		}
		report.BytesChanged += diffRange.Length
		report.HammingDistance += analysisEntry.HammingDistance
		report.HammingDistanceNon00orFF += analysisEntry.HammingDistanceNon00orFF
		report.Entries = append(report.Entries, analysisEntry)
	}
	return
}

type intervalTree struct {
	augmentedtree.Tree
}

type interval struct {
	IDValue uint64
	pkgbytes.Range
	Value interface{}
}

func (item *interval) LowAtDimension(_ uint64) int64 {
	return int64(item.Range.Offset)
}

func (item *interval) HighAtDimension(_ uint64) int64 {
	return int64(item.Range.Offset + item.Range.Length)
}

func (item *interval) OverlapsAtDimension(cmpIface augmentedtree.Interval, _ uint64) bool {
	cmp := cmpIface.(*interval)
	return item.Range.Intersect(cmp.Range)
}

func (item *interval) ID() uint64 {
	return item.IDValue
}

func newNodesIntervalTree(nodes []*ffs.Node) intervalTree {
	t := intervalTree{
		Tree: augmentedtree.New(1),
	}

	for idx, node := range nodes {
		t.Add(&interval{
			IDValue: uint64(idx),
			Range:   node.Range,
			Value:   node,
		})
	}

	return t
}

func newNamesIntervalTree(m map[string]pkgbytes.Ranges) intervalTree {
	t := intervalTree{
		Tree: augmentedtree.New(1),
	}

	idx := uint64(0)
	for name, ranges := range m {
		for _, _range := range ranges {
			t.Add(&interval{
				IDValue: idx,
				Range:   _range,
				Value:   name,
			})
			idx++
		}
	}

	return t
}

func (t *intervalTree) FindOverlapping(r pkgbytes.Range) []interface{} {
	var result []interface{}
	for _, item := range t.Tree.Query(&interval{
		Range: r,
	}) {
		result = append(result, item.(*interval).Value)
	}
	return result
}

// AddOffset just adds the offset to all offsets of the report
func (report *AnalysisReport) AddOffset(offset int64) {
	if report == nil {
		return
	}

	report.FirstProblemOffset += uint64(offset)
	for idx := range report.Entries {
		entry := &report.Entries[idx]
		entry.DiffRange.Offset += uint64(offset)
		for idx := range entry.RelatedMeasurements {
			measurement := entry.RelatedMeasurements[idx]
			for idx := range measurement.RelatedDataChunks {
				measurement.RelatedDataChunks[idx].Range.Offset += uint64(offset)
			}
			for idx := range measurement.Data {
				measurement.Data[idx].Range.Offset += uint64(offset)
			}
		}
	}
}

func nodesInfo(nodes []*ffs.Node) []NodeInfo {
	var result []NodeInfo
	for _, node := range nodes {

		// Gathering information

		var nodeType string
		var id string
		moduleName := node.ModuleName()
		switch f := node.Firmware.(type) {
		case *fianoUEFI.FirmwareVolume:
			nodeType = "volume"
		case *fianoUEFI.File:
			nodeType = "file"
		case *fianoUEFI.BIOSRegion:
			nodeType = "bios_region"
		default:
			nodeType = fmt.Sprintf("%T", f)
			if stringer, ok := f.(fmt.Stringer); ok {
				id = stringer.String()
			}
		}
		if id == `` {
			guid := node.GUID()
			if guid != nil {
				id = guid.String()
			}
		}

		// Compiling the string for the node

		var description strings.Builder
		description.WriteString(nodeType)
		if id != "" {
			description.WriteString(":" + id)
		}
		if moduleName != nil {
			description.WriteString(":" + *moduleName)
		}

		// Appending

		// TODO: do not String()-ify and then parse UUID, just use it as is.
		uuidValue, _ := uuid.Parse(id)
		result = append(result, NodeInfo{
			UUID:        uuidValue,
			Description: description.String(),
		})
	}
	return result
}
