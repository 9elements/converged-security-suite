// This package needs deep redesigning: there are more and more ways to do
// brute-forcing, so these modules should be flattened out instead of going
// coupling every method among each other.

package pcrbruteforcer

import (
	"bytes"
	"context"
	"fmt"
	"strings"

	"github.com/9elements/converged-security-suite/v2/pkg/bootflow/actors"
	"github.com/9elements/converged-security-suite/v2/pkg/bootflow/dataconverters"
	"github.com/9elements/converged-security-suite/v2/pkg/bootflow/datasources"
	"github.com/9elements/converged-security-suite/v2/pkg/bootflow/subsystems/trustchains/tpm"
	"github.com/9elements/converged-security-suite/v2/pkg/bootflow/systemartifacts/biosimage"
	"github.com/9elements/converged-security-suite/v2/pkg/bootflow/types"
	"github.com/9elements/converged-security-suite/v2/pkg/diff"
	"github.com/9elements/converged-security-suite/v2/pkg/tpmeventlog"
	"github.com/9elements/converged-security-suite/v2/pkg/uefi/ffs"
	"github.com/facebookincubator/go-belt/tool/logger"
	pkgbytes "github.com/linuxboot/fiano/pkg/bytes"
)

const (
	PhysAddrBase = tpmeventlog.PhysAddrBase
)

type logEntryExplanation struct {
	Event           *tpmeventlog.Event
	Measurement     *types.MeasuredData
	RelatedNodes    []diff.NodeInfo
	EventDataParsed *tpmeventlog.EventDataParsed
	DigestGuesses   [][]byte
}

func (e logEntryExplanation) String() string {
	var details []string

	switch {
	case e.Measurement != nil:
		details = append(details, fmt.Sprintf("reproduced the digest using measurement: %s", e.Measurement))
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
	for _, digest := range e.DigestGuesses {
		details = append(details, fmt.Sprintf("possible digest: %X", digest))
	}

	if len(details) == 0 {
		return fmt.Sprintf("<unable to get any info; event: %s>", e.Event)
	}

	return strings.Join(details, "; ")
}

func (e logEntryExplanation) guessMeasurement(
	ctx context.Context,
	s *types.State,
	expectedMeasurement *types.MeasuredData,
	ev *tpmeventlog.Event,
	image *biosimage.BIOSImage,
) (m *types.MeasuredData, digests [][]byte) {
	var digest []byte

	if e.EventDataParsed != nil {
		m, digest = e.guessMeasurementFromEventRanges(
			ctx,
			s,
			expectedMeasurement,
			ev,
			image,
		)
		if digest != nil {
			digests = append(digests, digest)
		}
		if m != nil {
			return
		}
	}

	if ev.Data != nil {
		m, digest = e.guessMeasurementFromEventRawData(
			s,
			ev,
		)
		if m != nil {
			// RawData is a pretty wild guess and more likely to mislead rather
			// than to give a hint so do not include the digest unless it matches.
			digests = append(digests, digest)
		}
	}

	return
}

func (e logEntryExplanation) guessMeasurementFromEventRawData(
	s *types.State,
	ev *tpmeventlog.Event,
) (*types.MeasuredData, []byte) {
	return tryMeasurement(s, ev, types.UnionForcedBytesOrReferences{{ForcedBytes: ev.Data}})
}

func (e logEntryExplanation) guessMeasurementFromEventRanges(
	ctx context.Context,
	s *types.State,
	expectedMeasurement *types.MeasuredData,
	ev *tpmeventlog.Event,
	image *biosimage.BIOSImage,
) (*types.MeasuredData, []byte) {
	var chunks types.UnionForcedBytesOrReferences
	for _, r := range e.EventDataParsed.Ranges {
		var addressMapper types.AddressMapper
		if isPhysAddr(r.Offset, image.Size()) {
			addressMapper = biosimage.PhysMemMapper{}
		}
		chunk := types.UnionForcedBytesOrReference{}
		if expectedMeasurement != nil {
			expectedForcedBytes := expectedMeasurement.Data.UnionForcedBytesOrReferences[len(chunks)].ForcedBytes
			if expectedForcedBytes != nil {
				chunk.ForcedBytes = expectedForcedBytes
			}
		}
		if r.Length > 0 {
			chunk.Reference = &types.Reference{
				Artifact:      image,
				AddressMapper: addressMapper,
				Ranges: []pkgbytes.Range{
					r,
				},
			}
		}
		if chunk.ForcedBytes == nil && chunk.Reference == nil {
			logger.FromCtx(ctx).Warnf("chunk.ForcedBytes == nil && chunk.Reference == nil")
			continue
		}
		chunks = append(chunks, chunk)
	}
	return tryMeasurement(s, ev, chunks)
}

func tryMeasurement(
	s *types.State,
	ev *tpmeventlog.Event,
	chunks types.UnionForcedBytesOrReferences,
) (*types.MeasuredData, []byte) {
	h, err := ev.Digest.HashAlgo.Hash()
	if err != nil {
		panic(err) // should never happen
	}
	tpm, err := tpm.GetFrom(s)
	if err != nil {
		panic(err) // should never happen
	}

	d := types.Data{
		UnionForcedBytesOrReferences: chunks,

		Converter: dataconverters.NewHasherFactory(h.New),
	}
	measurement := &types.MeasuredData{
		Data:       d,
		DataSource: (*datasources.StaticData)(&d),
		Actor:      actors.Unknown{},
		TrustChain: tpm,
	}

	digest := measurement.ConvertedBytes()
	if !bytes.Equal(ev.Digest.Digest, digest) {
		return nil, digest
	}

	return measurement, digest
}

func isPhysAddr(addr, imageSize uint64) bool {
	return addr >= (PhysAddrBase-imageSize) && addr < PhysAddrBase
}

func (e *logEntryExplanation) calculateRelatedNodes(
	image *biosimage.BIOSImage,
) {
	fw, err := image.Parse()
	if err != nil {
		return
	}

	var allRanges pkgbytes.Ranges
	if e.Measurement != nil {
		allRanges = append(allRanges, e.Measurement.References().Ranges()...)
	}
	if e.EventDataParsed != nil {
		for _, r := range e.EventDataParsed.Ranges {
			if isPhysAddr(r.Offset, image.Size()) {
				r.Offset -= PhysAddrBase - image.Size()
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
	ctx context.Context,
	s *types.State,
	expectedMeasurement *types.MeasuredData,
	ev *tpmeventlog.Event,
) logEntryExplanation {
	result := logEntryExplanation{Event: ev}

	image, err := biosimage.Get(s)
	if err != nil {
		// TODO: print the error
		return result
	}

	result.EventDataParsed, _ = tpmeventlog.ParseEventData(ev, image.Size())
	//if err != nil {
	//	TODO: print the error
	//}
	result.Measurement, result.DigestGuesses = result.guessMeasurement(ctx, s, expectedMeasurement, ev, image)

	result.calculateRelatedNodes(image)
	return result
}
