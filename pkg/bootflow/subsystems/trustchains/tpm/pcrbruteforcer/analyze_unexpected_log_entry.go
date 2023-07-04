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

type logEntryExplainer struct {
	Event           *tpmeventlog.Event
	Measurement     types.MeasuredDataSlice
	RelatedNodes    []diff.NodeInfo
	EventDataParsed *tpmeventlog.EventDataParsed
	DigestGuesses   [][]byte
}

func (e logEntryExplainer) String() string {
	var details []string

	if e.Measurement != nil {
		details = append(details, fmt.Sprintf("reproduced the digest using measurement: %s", strings.ReplaceAll(e.Measurement.String(), "\n", "; ")))
	}
	if e.EventDataParsed != nil {
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
		details = append(details, fmt.Sprintf("digest guessed from Data field: %X", digest))
	}

	if len(details) == 0 {
		return fmt.Sprintf("<unable to get any info; event: %s>", e.Event)
	}

	return strings.Join(details, "; ")
}

func (e logEntryExplainer) guessMeasurement(
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

func (e logEntryExplainer) guessMeasurementFromEventRawData(
	s *types.State,
	ev *tpmeventlog.Event,
) (*types.MeasuredData, []byte) {
	return tryMeasurement(s, ev, types.References{*types.NewReference(types.RawBytes(ev.Data))})
}

func (e logEntryExplainer) guessMeasurementFromEventRanges(
	ctx context.Context,
	s *types.State,
	expectedMeasurement *types.MeasuredData,
	ev *tpmeventlog.Event,
	image *biosimage.BIOSImage,
) (*types.MeasuredData, []byte) {
	return tryMeasurement(s, ev, rangesToChunks(
		ctx,
		image,
		e.EventDataParsed.Ranges,
		expectedMeasurement,
	))
}

func rangesToChunks(
	ctx context.Context,
	image *biosimage.BIOSImage,
	ranges pkgbytes.Ranges,
	expectedMeasurement *types.MeasuredData,
) types.References {
	var chunks types.References
	for _, r := range ranges {
		var addressMapper types.AddressMapper
		if isPhysAddr(r.Offset, image.Size()) {
			addressMapper = biosimage.PhysMemMapper{}
		}

		var chunk *types.Reference

		// If this measurement measures some pre-hardcoded value instead of
		// actually measuring the BIOS image, then re-used the hardcoded value:
		if expectedMeasurement != nil {
			art := expectedMeasurement.Data.References[len(chunks)].Artifact
			if b, ok := art.(types.RawBytes); ok {
				chunk = types.NewReference(b)
			}
		}

		// An actual measurement:
		if r.Length > 0 {
			if chunk != nil {
				logger.Error(ctx, "has RawBytes and a Range at the same time, supposed to be impossible; dropping the ForcedBytes part")
			}
			chunk = &types.Reference{
				Artifact: image,
				MappedRanges: types.MappedRanges{
					AddressMapper: addressMapper,
					Ranges:        []pkgbytes.Range{r},
				},
			}
		}

		if chunk == nil {
			logger.Warn(ctx, "neither RawBytes nor Range are set, skipping the chunk")
			continue
		}

		chunks = append(chunks, *chunk)
	}
	return chunks
}

func tryMeasurement(
	s *types.State,
	ev *tpmeventlog.Event,
	chunks types.References,
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
		References: chunks,
		Converter:  dataconverters.NewHasherFactory(h.New),
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

func (e *logEntryExplainer) calculateRelatedNodes(
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

func (e *logEntryExplainer) SetMeasurement(
	artifact types.SystemArtifact,
	trustChain types.TrustChain,
	dataConverter types.DataConverter,
	addrMapper types.AddressMapper,
	ranges pkgbytes.Ranges,
) {
	e.Measurement = e.Measurement[:0]
	e.AddMeasurement(artifact, trustChain, dataConverter, addrMapper, ranges)
}

func (e *logEntryExplainer) AddMeasurement(
	artifact types.SystemArtifact,
	trustChain types.TrustChain,
	dataConverter types.DataConverter,
	addrMapper types.AddressMapper,
	ranges pkgbytes.Ranges,
) {
	data := *types.NewData(&types.Reference{
		Artifact: artifact,
		MappedRanges: types.MappedRanges{
			AddressMapper: addrMapper,
			Ranges:        ranges,
		},
	})
	data.Converter = dataConverter
	e.Measurement = append(e.Measurement, types.MeasuredData{
		Data:       data,
		TrustChain: trustChain,
	})
}

func newLogEntryExplainer(
	ctx context.Context,
	s *types.State,
	expectedMeasurement *types.MeasuredData,
	ev *tpmeventlog.Event,
) *logEntryExplainer {
	result := logEntryExplainer{Event: ev}

	image, err := biosimage.Get(s)
	if err != nil {
		// TODO: print the error
		return &result
	}

	result.EventDataParsed, _ = tpmeventlog.ParseEventData(ev, image.Size())
	//if err != nil {
	//	TODO: print the error
	//}
	measurement, digestGuesses := result.guessMeasurement(ctx, s, expectedMeasurement, ev, image)
	if measurement != nil {
		result.Measurement = append(result.Measurement, *measurement)
	}
	result.DigestGuesses = digestGuesses

	result.calculateRelatedNodes(image)
	return &result
}
