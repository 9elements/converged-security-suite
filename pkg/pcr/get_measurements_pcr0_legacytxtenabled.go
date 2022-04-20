package pcr

import (
	"crypto/sha1"
	"crypto/sha256"
	"encoding/binary"
	"fmt"

	"github.com/9elements/converged-security-suite/v2/pkg/errors"
	"github.com/linuxboot/fiano/pkg/intel/metadata/fit"
	"github.com/linuxboot/fiano/pkg/intel/metadata/manifest"
)

// MeasureInit returns the fake measurement for TPM initialization, it
// is used to match EventLog with expected measurements.
func MeasureInit() *Measurement {
	return NewStaticDataMeasurement(MeasurementIDInit, nil)
}

// MeasureACM returns a fake measurement of ACM.
func MeasureACM(imageSize uint64, fitEntries []fit.Entry) (*Measurement, error) {
	m := Measurement{
		ID: MeasurementIDACM,
	}

	mErr := &errors.MultiError{}

	for _, fitEntry := range fitEntries {
		switch fitEntry := fitEntry.(type) {
		case *fit.EntrySACM: // startup AC module entry
			_ = mErr.Add(fitEntry.HeadersErrors...)
			acmOffset := fitEntry.Headers.Address.Offset(imageSize)
			m.Data = append(m.Data, *NewRangeDataChunk(0, acmOffset, uint64(len(fitEntry.DataSegmentBytes))))
		}
	}

	if len(m.Data) == 0 {
		return nil, ErrNoSACM{}
	}

	return &m, mErr.ReturnValue()
}

// MeasureACMDate returns a measurement of ACM date.
func MeasureACMDate(imageSize uint64, fitEntries []fit.Entry) (*Measurement, error) {
	m := Measurement{
		ID: MeasurementIDACMDate,
	}

	mErr := &errors.MultiError{}
	found := false
	for _, fitEntry := range fitEntries {
		switch fitEntry := fitEntry.(type) {
		case *fit.EntrySACM: // startup AC module entry
			found = true

			_ = mErr.Add(fitEntry.HeadersErrors...)
			data, err := fitEntry.ParseData()
			if err != nil {
				_ = mErr.Add(err)
			}
			if data == nil {
				continue
			}

			sacmOffset := fitEntry.Headers.Address.Offset(imageSize)
			offset := sacmOffset + uint64(data.DateBinaryOffset())
			length := uint64(binary.Size(data.GetDate()))

			m.Data = append(m.Data, *NewRangeDataChunk(0, offset, length))
		}
	}

	if !found {
		_ = mErr.Add(ErrNoSACM{})
	}

	if len(m.Data) == 0 {
		return nil, mErr.ReturnValue()
	}
	return &m, mErr.ReturnValue()
}

// MeasureACMDateInPlace returns a measurement of ACM date, but without hashing
// it (it is used in obsolete TPM1.2 flows; a bug of the initial implementation?).
func MeasureACMDateInPlace(hashAlg manifest.Algorithm, imageSize uint64, fitEntries []fit.Entry) (*Measurement, error) {
	m := Measurement{
		ID: MeasurementIDACMDateInPlace,
	}

	var hashSize int
	switch hashAlg {
	case manifest.AlgSHA1:
		hashSize = sha1.New().Size()
	case manifest.AlgSHA256:
		hashSize = sha256.New().Size()
	default:
		return nil, fmt.Errorf("unknown hash algorithm: %v", hashAlg)
	}

	mErr := &errors.MultiError{}
	found := false
	for _, fitEntry := range fitEntries {
		switch fitEntry := fitEntry.(type) {
		case *fit.EntrySACM: // startup AC module entry
			found = true

			_ = mErr.Add(fitEntry.HeadersErrors...)
			data, err := fitEntry.ParseData()
			if err != nil {
				_ = mErr.Add(err)
			}
			if data == nil {
				continue
			}

			sacmOffset := fitEntry.Headers.Address.Offset(imageSize)
			offset := sacmOffset + uint64(data.DateBinaryOffset())
			length := uint64(binary.Size(data.GetDate()))

			m.Data = append(m.Data, *NewRangeDataChunk(DataChunkIDUndefined, offset, length))
			padding := make([]byte, uint64(hashSize)-length)
			m.Data = append(m.Data, *NewStaticDataChunk(DataChunkIDUndefined, padding))
		}
	}

	if !found {
		_ = mErr.Add(ErrNoSACM{})
	}

	if len(m.Data) == 0 {
		return nil, mErr.ReturnValue()
	}
	return &m, mErr.ReturnValue()
}

// MeasureBIOSStartupModule return the measurement of BIOS startup module.
func MeasureBIOSStartupModule(imageSize uint64, fitEntries []fit.Entry) (*Measurement, error) {
	m := Measurement{
		ID: MeasurementIDBIOSStartupModule,
	}

	mErr := &errors.MultiError{}
	for _, fitEntry := range fitEntries {
		switch fitEntry := fitEntry.(type) {
		case *fit.EntryBIOSStartupModuleEntry:
			_ = mErr.Add(fitEntry.HeadersErrors...)

			biosSMOffset := fitEntry.Headers.Address.Offset(imageSize)
			biosStartup, err := DataChunkIDBIOSStartup(uint(len(m.Data)))
			if err != nil {
				return nil, err
			}
			m.Data = append(m.Data,
				*NewRangeDataChunk(
					biosStartup,
					biosSMOffset,
					uint64(len(fitEntry.DataSegmentBytes)),
				),
			)
		}
	}

	return &m, mErr.ReturnValue()
}

// MeasureSCRTMSeparator return the measurement which separates hardware S-RTM
// measurements from the rest firmware measurements.
func MeasureSCRTMSeparator() *Measurement {
	return NewStaticDataMeasurement(MeasurementIDSCRTMSeparator, Separator)
}
