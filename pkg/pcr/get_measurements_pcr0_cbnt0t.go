package pcr

import (
	"encoding/binary"
	"fmt"

	"github.com/9elements/converged-security-suite/v2/pkg/registers"
	pkgbytes "github.com/linuxboot/fiano/pkg/bytes"
	"github.com/linuxboot/fiano/pkg/intel/metadata/bg/bgbootpolicy"
	"github.com/linuxboot/fiano/pkg/intel/metadata/bg/bgkey"
	"github.com/linuxboot/fiano/pkg/intel/metadata/cbnt"
	"github.com/linuxboot/fiano/pkg/intel/metadata/cbnt/cbntbootpolicy"
	"github.com/linuxboot/fiano/pkg/intel/metadata/cbnt/cbntkey"
	"github.com/linuxboot/fiano/pkg/intel/metadata/fit"
)

type pcr0Data struct {
	acmPolicyStatus uint64
	acmHeaderSVN    pkgbytes.Range
	acmSignature    pkgbytes.Range
	kmSignature     pkgbytes.Range
	bpmSignature    pkgbytes.Range
	ibbDigest       pkgbytes.Range
}

// Measurement returns pcr0Data as a Measurement.
func (d pcr0Data) Measurement() *Measurement {
	var dataChunks []DataChunk
	acmPolicyStatusChunk := DataChunk{
		ID:        DataChunkIDACMPolicyStatus,
		ForceData: make([]byte, 8),
	}
	binary.LittleEndian.PutUint64(acmPolicyStatusChunk.ForceData, d.acmPolicyStatus)
	dataChunks = append(dataChunks, acmPolicyStatusChunk)

	dataChunks = append(dataChunks, *NewRangeDataChunk(DataChunkIDACMHeaderSVN, d.acmHeaderSVN.Offset, d.acmHeaderSVN.Length))
	dataChunks = append(dataChunks, *NewRangeDataChunk(DataChunkIDACMSignature, d.acmSignature.Offset, d.acmSignature.Length))
	dataChunks = append(dataChunks, *NewRangeDataChunk(DataChunkIDKeyManifestSignature, d.kmSignature.Offset, d.kmSignature.Length))
	dataChunks = append(dataChunks, *NewRangeDataChunk(DataChunkIDBootPolicyManifestSignature, d.bpmSignature.Offset, d.bpmSignature.Length))
	dataChunks = append(dataChunks, *NewRangeDataChunk(DataChunkIDIBBDigest, d.ibbDigest.Offset, d.ibbDigest.Length))

	return &Measurement{
		ID:   MeasurementIDPCR0DATA,
		Data: dataChunks,
	}
}

// MeasurePCR0Data returns a PCR0_DATA measurement.
func MeasurePCR0Data(config MeasurementConfig, imageSize uint64, fitEntries []fit.Entry) (*Measurement, error) {
	var data pcr0Data

	acmPolicyStatus, found := registers.FindACMPolicyStatus(config.Registers)
	if !found {
		return nil, fmt.Errorf("no ACM_POLICY_STATUS register")
	}
	data.acmPolicyStatus = acmPolicyStatus.Raw()

	acmEntry, acmFITEntry, err := getACM(fitEntries)
	if err != nil {
		return nil, err
	}

	acmOffset := acmFITEntry.GetEntryBase().Headers.Address.Offset(imageSize)

	// From Intel CBnT doc: "SVN field of ACM header (offset 28) indicates..."
	// Offset 28 == TxtSVN
	data.acmHeaderSVN = pkgbytes.Range{
		Offset: acmOffset + acmEntry.GetCommon().TXTSVNBinaryOffset(),
		Length: uint64(binary.Size(acmEntry.GetTXTSVN())),
	}
	data.acmSignature = pkgbytes.Range{
		Offset: acmOffset + acmEntry.RSASigBinaryOffset(),
		Length: uint64(len(acmEntry.GetRSASig())),
	}

	keyManifest1, keyManifest2, keyManifestFITEntry, err := getKeyManifest(fitEntries)
	if err != nil {
		return nil, err
	}
	kmOffset := keyManifestFITEntry.Headers.Address.Offset(imageSize)
	if keyManifest1 != nil {
		data.kmSignature = pkgbytes.Range{
			Offset: kmOffset + keyManifest1.KeyAndSignatureOffset() + keyManifest1.KeyAndSignature.SignatureOffset() + keyManifest1.KeyAndSignature.Signature.DataOffset(),
			Length: uint64(len(keyManifest1.KeyAndSignature.Signature.Data)),
		}
	} else {
		data.kmSignature = pkgbytes.Range{
			Offset: kmOffset + keyManifest2.KeyAndSignatureOffset() + keyManifest2.KeyAndSignature.SignatureOffset() + keyManifest2.KeyAndSignature.Signature.DataOffset(),
			Length: uint64(len(keyManifest2.KeyAndSignature.Signature.Data)),
		}
	}

	bpManifest1, bpManifest2, bpManifestFITEntry, err := getBootPolicyManifest(fitEntries)
	if err != nil {
		return nil, err
	}
	bpmOffset := bpManifestFITEntry.Headers.Address.Offset(imageSize)

	var (
		offsetToTheFirstDigest uint64
		digests                []cbnt.HashStructure
	)
	if bpManifest1 != nil {
		data.bpmSignature = pkgbytes.Range{
			Offset: bpmOffset + uint64(bpManifest1.PMSEOffset()+bpManifest1.PMSE.KeySignatureOffset()) + bpManifest1.PMSE.SignatureOffset() + bpManifest1.PMSE.Signature.DataOffset(),
			Length: uint64(len(bpManifest1.PMSE.Signature.Data)),
		}
		digests = []cbnt.HashStructure{{
			HashAlg:    cbnt.Algorithm(bpManifest1.SE[0].Digest.HashAlg),
			HashBuffer: bpManifest1.SE[0].Digest.HashBuffer,
		}}
		if len(digests) == 0 {
			return nil, fmt.Errorf("IBBDigest list is empty")
		}
		// Note: +2 - skip array size field to get the first element
		offsetToTheFirstDigest = bpmOffset + bpManifest1.SEOffset() +
			bpManifest1.SE[0].DigestOffset() + 2
	} else {
		data.bpmSignature = pkgbytes.Range{
			Offset: bpmOffset + uint64(bpManifest2.KeySignatureOffset) + bpManifest2.PMSE.SignatureOffset() + bpManifest2.PMSE.Signature.DataOffset(),
			Length: uint64(len(bpManifest2.PMSE.Signature.Data)),
		}

		digests = bpManifest2.SE[0].DigestList.List
		if len(digests) == 0 {
			return nil, fmt.Errorf("IBBDigest list is empty")
		}
		// Note: +2 - skip array size field to get the first element
		offsetToTheFirstDigest = bpmOffset + bpManifest2.SEOffset() +
			bpManifest2.SE[0].DigestListOffset() + (bpManifest2.SE[0].DigestList.ListOffset() + 2)

	}
	if config.PCR0DataIbbDigestHashAlgorithm == cbnt.AlgUnknown || config.PCR0DataIbbDigestHashAlgorithm == cbnt.AlgNull {
		// take the fist element as stated in the doc above
		data.ibbDigest = pkgbytes.Range{
			Offset: offsetToTheFirstDigest + (digests[0].HashBufferOffset() + 2),
			Length: uint64(len(digests[0].HashBuffer)),
		}
	} else {
		// find ibbDigest with the required algorithm
		offsetToCurrentDigest := offsetToTheFirstDigest
		var found bool
		for idx := range digests {
			if digests[idx].HashAlg == config.PCR0DataIbbDigestHashAlgorithm {
				data.ibbDigest = pkgbytes.Range{
					Offset: offsetToCurrentDigest + (digests[idx].HashBufferOffset() + 2),
					Length: uint64(len(digests[idx].HashBuffer)),
				}
				found = true
				break
			}
			offsetToCurrentDigest += digests[idx].TotalSize()
		}

		if !found {
			return nil, fmt.Errorf("no IBBDigest with hash algorithm: %v", config.PCR0DataIbbDigestHashAlgorithm)
		}
	}

	return data.Measurement(), nil
}

func getACM(fitEntries []fit.Entry) (*fit.EntrySACMData, *fit.EntrySACM, error) {
	for _, fitEntry := range fitEntries {
		switch fitEntry := fitEntry.(type) {
		case *fit.EntrySACM:
			acmData, err := fitEntry.ParseData()
			if err != nil {
				return nil, nil, fmt.Errorf("failed to parse ACM, err: %v", err)
			}
			return acmData, fitEntry, nil
		}
	}
	return nil, nil, fmt.Errorf("ACM FIT entry is not found")
}

func getKeyManifest(fitEntries []fit.Entry) (*bgkey.Manifest, *cbntkey.Manifest, *fit.EntryKeyManifestRecord, error) {
	for _, fitEntry := range fitEntries {
		switch fitEntry := fitEntry.(type) {
		case *fit.EntryKeyManifestRecord:
			km1, km2, err := fitEntry.ParseData()
			if err != nil {
				return nil, nil, nil, err
			}
			return km1, km2, fitEntry, nil
		}
	}
	return nil, nil, nil, fmt.Errorf("key manifest FIT entry is not found")
}

func getBootPolicyManifest(fitEntries []fit.Entry) (*bgbootpolicy.Manifest, *cbntbootpolicy.Manifest, *fit.EntryBootPolicyManifestRecord, error) {
	for _, fitEntry := range fitEntries {
		switch fitEntry := fitEntry.(type) {
		case *fit.EntryBootPolicyManifestRecord:
			bpManifest1, bpManifest2, err := fitEntry.ParseData()
			if err != nil {
				return nil, nil, nil, err
			}
			return bpManifest1, bpManifest2, fitEntry, nil
		}
	}
	return nil, nil, nil, fmt.Errorf("boot policy manifest FIT entry is not found")
}

// MeasureKeyManifest returns a measurement containing CBnT key cbnt.
func MeasureKeyManifest(imageSize uint64, fitEntries []fit.Entry) (*Measurement, error) {
	_, _, kmFITEntry, err := getKeyManifest(fitEntries)
	if err != nil {
		return nil, fmt.Errorf("unable to get key manifest (KM): %w", err)
	}

	return &Measurement{
		ID: MeasurementIDKeyManifest,
		Data: DataChunks{{
			Range: pkgbytes.Range{
				Offset: kmFITEntry.Headers.Address.Offset(imageSize),
				Length: uint64(len(kmFITEntry.DataSegmentBytes)),
			},
		}},
	}, nil
}

// MeasureBootPolicy returns a measurement containing CBnT key cbnt.
func MeasureBootPolicy(imageSize uint64, fitEntries []fit.Entry) (*Measurement, error) {
	_, _, bpmFITEntry, err := getBootPolicyManifest(fitEntries)
	if err != nil {
		return nil, fmt.Errorf("unable to get boot policy manifest (BPM): %w", err)
	}

	return &Measurement{
		ID: MeasurementIDBootPolicyManifest,
		Data: DataChunks{{
			Range: pkgbytes.Range{
				Offset: bpmFITEntry.Headers.Address.Offset(imageSize),
				Length: uint64(len(bpmFITEntry.DataSegmentBytes)),
			},
		}},
	}, nil
}

// MeasureIBB returns a measurement containing IBB according to BPM.
func MeasureIBB(fitEntries []fit.Entry, firmwareSize uint64) (*Measurement, error) {
	bpManifest1, bpManifest2, _, err := getBootPolicyManifest(fitEntries)
	if err != nil {
		return nil, fmt.Errorf("unable to get boot policy manifest (BPM): %w", err)
	}

	result := Measurement{
		ID: MeasurementIDIBBFake,
	}
	var ibbRanges pkgbytes.Ranges
	if bpManifest1 != nil {
		ibbRanges = bpManifest1.IBBDataRanges(firmwareSize)
	} else {
		ibbRanges = bpManifest2.IBBDataRanges(firmwareSize)
	}
	for _, _range := range ibbRanges {
		result.Data = append(result.Data, DataChunk{
			Range: _range,
		})
	}

	return &result, nil
}
