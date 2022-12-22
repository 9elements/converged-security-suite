package pcrbruteforcer

import (
	"bytes"
	"fmt"
	"strings"

	"github.com/9elements/converged-security-suite/v2/pkg/diff"
	"github.com/9elements/converged-security-suite/v2/pkg/pcr"
	"github.com/9elements/converged-security-suite/v2/pkg/tpmeventlog"
	"github.com/9elements/converged-security-suite/v2/pkg/uefi"
	"github.com/9elements/converged-security-suite/v2/pkg/uefi/ffs"
	pkgbytes "github.com/linuxboot/fiano/pkg/bytes"
)

const (
	PhysAddrBase = tpmeventlog.PhysAddrBase
)

type logEntryExplanation struct {
	Measurement     *pcr.Measurement
	RelatedNodes    []diff.NodeInfo
	EventDataParsed *tpmeventlog.EventDataParsed
}

func formatMeasurement(m pcr.Measurement) string {
	var result []string
	for _, chunk := range m.Data {
		if chunk.ForceData != nil {
			result = append(result, fmt.Sprintf(`{"ForceData": "0x%X"}`, chunk.ForceData))
			continue
		}
		result = append(result, fmt.Sprintf(`{"Range": %s}`, chunk.Range))
	}
	return "{" + strings.Join(result, ", ") + "}"
}

func (e logEntryExplanation) String() string {
	var details []string

	switch {
	case e.Measurement != nil:
		details = append(details, fmt.Sprintf("reproduced the digest using measurement: %v", formatMeasurement(*e.Measurement)))
	case e.EventDataParsed != nil:
		if len(e.EventDataParsed.Ranges) > 0 {
			details = append(details, fmt.Sprintf("mentioned byte ranges: %v", e.EventDataParsed.Ranges))
		}
		if len(e.EventDataParsed.FvGUIDs) > 0 {
			details = append(details, fmt.Sprintf("mentioned UUIDs: %v", e.EventDataParsed.FvGUIDs))
		}
	}

	if len(e.RelatedNodes) != 0 {
		details = append(details, fmt.Sprintf("related UEFI nodes: %s", e.RelatedNodes))
	}

	if len(details) == 0 {
		return "<unable to get any info>"
	}

	return strings.Join(details, "; ")
}

func (e logEntryExplanation) guessMeasurement(
	expectedMeasurement *pcr.Measurement,
	ev *tpmeventlog.Event,
	image []byte,
) *pcr.Measurement {
	if e.EventDataParsed != nil {
		m := e.guessMeasurementFromEventRanges(
			expectedMeasurement,
			ev,
			image,
		)
		if m != nil {
			return m
		}
	}

	return e.guessMeasurementFromEventRawData(
		expectedMeasurement,
		ev,
	)
}

func (e logEntryExplanation) guessMeasurementFromEventRawData(
	expectedMeasurement *pcr.Measurement,
	ev *tpmeventlog.Event,
) *pcr.Measurement {
	return tryMeasurement(expectedMeasurement, ev, nil, pcr.DataChunks{{ID: pcr.DataChunkIDUnknown, ForceData: ev.Data}})
}

func (e logEntryExplanation) guessMeasurementFromEventRanges(
	expectedMeasurement *pcr.Measurement,
	ev *tpmeventlog.Event,
	image []byte,
) *pcr.Measurement {
	var chunks pcr.DataChunks
	for _, r := range e.EventDataParsed.Ranges {
		if isPhysAddr(r.Offset, uint64(len(image))) {
			r.Offset -= PhysAddrBase - uint64(len(image))
		}
		chunkID := pcr.DataChunkIDUnknown
		var forceData []byte
		if expectedMeasurement != nil && len(expectedMeasurement.Data) >= len(chunks) {
			chunkID = expectedMeasurement.Data[len(chunks)].ID
			forceData = expectedMeasurement.Data[len(chunks)].ForceData
		}
		chunks = append(chunks, pcr.DataChunk{
			ID:        chunkID,
			Range:     r,
			ForceData: forceData,
		})
	}
	return tryMeasurement(expectedMeasurement, ev, image, chunks)
}

func tryMeasurement(
	expectedMeasurement *pcr.Measurement,
	ev *tpmeventlog.Event,
	image []byte,
	chunks pcr.DataChunks,
) *pcr.Measurement {
	measurementID := pcr.MeasurementIDUnknown
	if expectedMeasurement != nil {
		measurementID = expectedMeasurement.ID
	}
	measurement := &pcr.Measurement{
		ID:   measurementID,
		Data: chunks,
	}
	h, err := ev.Digest.HashAlgo.Hash()
	if err != nil {
		panic(err) // should never happen
	}
	digest, err := measurement.Calculate(image, h.New())
	if err != nil {
		panic(err) // should never happen
	}
	if !bytes.Equal(ev.Digest.Digest, digest) {
		return nil
	}
	return measurement
}

func isPhysAddr(addr, imageSize uint64) bool {
	return addr >= (PhysAddrBase-imageSize) && addr < PhysAddrBase
}

func (e *logEntryExplanation) calculateRelatedNodes(
	image []byte,
) {
	fw, err := uefi.ParseUEFIFirmwareBytes(image)
	if err != nil {
		return
	}

	var allRanges pkgbytes.Ranges
	if e.Measurement != nil {
		allRanges = append(allRanges, e.Measurement.Ranges()...)
	}
	if e.EventDataParsed != nil {
		for _, r := range e.EventDataParsed.Ranges {
			if isPhysAddr(r.Offset, uint64(len(image))) {
				r.Offset -= PhysAddrBase - uint64(len(image))
			}
			allRanges = append(allRanges, r)
		}

		for _, guid := range e.EventDataParsed.FvGUIDs {
			nodes, _ := fw.GetByGUID(guid)
			//if err != nil {
			//	TODO: print the error
			//}
			for _, node := range nodes {
				if node.Length != 0 {
					allRanges = append(allRanges, node.Range)
				}
			}
		}
	}

	var allNodes []*ffs.Node
	allRanges.SortAndMerge()
	for _, r := range allRanges {
		nodes, _ := fw.GetByRange(r)
		//if err != nil {
		//	TODO: print the error
		//}
		allNodes = append(allNodes, nodes...)
	}

	e.RelatedNodes = diff.GetNodesInfo(allNodes)
}

func explainLogEntry(
	expectedMeasurement *pcr.Measurement,
	ev *tpmeventlog.Event,
	image []byte,
) logEntryExplanation {
	var result logEntryExplanation

	result.EventDataParsed, _ = tpmeventlog.ParseEventData(ev, uint64(len(image)))
	//if err != nil {
	//	TODO: print the error
	//}
	result.Measurement = result.guessMeasurement(expectedMeasurement, ev, image)

	result.calculateRelatedNodes(image)
	return result
}
