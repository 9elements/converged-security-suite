package pcr

import (
	"encoding/binary"

	"github.com/9elements/converged-security-suite/v2/pkg/errors"
	"github.com/9elements/converged-security-suite/v2/pkg/intel/metadata/fit"
)

func MeasureInit() *Measurement {
	return NewStaticDataMeasurement(MeasurementIDInit, nil)
}

func MeasureACMDate(fitEntries []fit.Entry) (*Measurement, error) {
	m := Measurement{
		ID: MeasurementIDACMDate,
	}

	mErr := &errors.MultiError{}
	for _, fitEntry := range fitEntries {
		switch fitEntry := fitEntry.(type) {
		case *fit.EntrySACM: // startup AC module entry

			mErr.Add(fitEntry.HeadersErrors...)
			data, err := fitEntry.ParseData()
			if err != nil {
				mErr.Add(err)
			}

			if data == nil {
				continue
			}

			offset := fitEntry.GetDataOffset() + uint64(data.DateBinaryOffset())
			length := uint64(binary.Size(data.GetDate()))

			m.Data = append(m.Data, *NewRangeDataChunk(0, offset, length))
		}
	}

	return &m, mErr.ReturnValue()
}

func MeasureBIOSStartupModule(fitEntries []fit.Entry) (*Measurement, error) {
	m := Measurement{
		ID: MeasurementIDBIOSStartupModule,
	}

	mErr := &errors.MultiError{}
	for _, fitEntry := range fitEntries {
		switch fitEntry := fitEntry.(type) {
		case *fit.EntryBIOSStartupModuleEntry:
			mErr.Add(fitEntry.HeadersErrors...)

			m.Data = append(m.Data,
				*NewRangeDataChunk(
					DataChunkIDBIOSStartup(uint(len(m.Data))),
					fitEntry.GetDataOffset(),
					uint64(len(fitEntry.DataBytes)),
				),
			)
		}
	}

	return &m, mErr.ReturnValue()
}

func MeasureSCRTMSeparator() *Measurement {
	return NewStaticDataMeasurement(MeasurementIDSCRTMSeparator, Separator)
}
