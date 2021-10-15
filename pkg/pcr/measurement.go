package pcr

import (
	"encoding/json"
	"fmt"
	"hash"
	"reflect"

	"github.com/9elements/converged-security-suite/v2/pkg/bytes"
	"github.com/9elements/converged-security-suite/v2/pkg/tpmeventlog"
)

var (
	// LoggingDataLimit is a limit of how many bytes of a measured data
	// to write per measurement. It is takes arbitrary (feel free to change it):
	LoggingDataLimit = uint(20)
)

// DataChunk contains a chunk of data that is measured during one measurement.
// It could be a range of bytes inside firmware placed in `Range` or if `ForceData` is not nil,
// then it is used as the measurable data instead of `Range`.
type DataChunk struct {
	ID DataChunkID `json:",omitempty"`

	// Range contains byte range of the firmware to be measured
	Range bytes.Range `json:",omitempty"`

	// ForceData is used to define hard-coded values.
	ForceData []byte `json:",omitempty"`
}

// String implements fmt.Stringer
func (chunk DataChunk) String() string {
	m := map[string]string{}
	m["ID"] = chunk.ID.String()
	if chunk.ForceData != nil {
		m["ForceData"] = fmt.Sprintf("0x%X", chunk.ForceData)
	} else {
		m["Offset"] = fmt.Sprintf("0x%X", chunk.Range.Offset)
		m["Length"] = fmt.Sprintf("0x%X", chunk.Range.Length)
	}
	b, err := json.Marshal(m)
	if err != nil {
		panic(err)
	}
	return string(b)
}

// Find returns the chunk with the specified DataChunkID.
// Or returns nil if such data chunk was not found.
func (s DataChunks) Find(id DataChunkID) *DataChunk {
	for idx := range s {
		d := &s[idx]
		if d.ID == id {
			return d
		}
	}

	return nil
}

// Copy performs a deep copy.
func (chunk DataChunk) Copy() *DataChunk {
	if chunk.ForceData != nil {
		forceData := make([]byte, len(chunk.ForceData))
		copy(forceData, chunk.ForceData)
		chunk.ForceData = forceData
	}
	return &chunk
}

// CompileMeasurableData returns the data to be measured.
func (chunk DataChunk) CompileMeasurableData(image []byte) []byte {
	if chunk.ForceData != nil {
		return chunk.ForceData
	}
	return image[chunk.Range.Offset : chunk.Range.Offset+chunk.Range.Length]
}

// DataChunks is a set of DataChunk-s.
type DataChunks []DataChunk

// Ranges returns a slice of all Range-s where ForceData is nil.
func (s DataChunks) Ranges() bytes.Ranges {
	var r bytes.Ranges
	for _, chunk := range s {
		if chunk.ForceData != nil {
			continue
		}
		r = append(r, chunk.Range)
	}
	return r
}

// Copy performs a deep copy.
func (s DataChunks) Copy() DataChunks {
	if s == nil {
		return nil
	}

	c := make(DataChunks, 0, len(s))
	for _, data := range s {
		c = append(c, *data.Copy())
	}
	return c
}

// NewStaticDataChunk returns a DataChunk based on a predefined value.
func NewStaticDataChunk(id DataChunkID, data []byte) *DataChunk {
	return &DataChunk{
		ID:        id,
		ForceData: data,
	}
}

// NewRangeDataChunk returns a DataChunk based on image data.
func NewRangeDataChunk(id DataChunkID, offset uint64, length uint64) *DataChunk {
	r := bytes.Range{
		Offset: offset,
		Length: length,
	}
	return &DataChunk{
		ID:    id,
		Range: r,
	}
}

// MeasureEvent describes a measurement event that can calculate the hash given the data
type MeasureEvent interface {
	// NOTE: this would normally be named ID() but it conflicts with Measurement.ID that
	// will implement this interface later on
	GetID() MeasurementID
	CompileMeasurableData(image []byte) []byte
	Calculate(image []byte, hasher hash.Hash) ([]byte, error)
}

// Measurement is the key structure of all packages `pcr0/...`.
//
// It defines one PCR measurement. Usually it means to extend the
// PCR value with a hash of bytes referenced by `DataChunk`.
type Measurement struct {
	// ID is the unique identifier of the PCR measurement.
	ID MeasurementID

	// Data contains chunks of data to be measured as contiguous sequence of bytes
	Data DataChunks `json:",omitempty"`
}

func eventTypePtr(t tpmeventlog.EventType) *tpmeventlog.EventType {
	return &t
}

// GetID return the measurement ID
func (m Measurement) GetID() MeasurementID {
	return m.ID
}

// IsFake forces to skip this measurement in real PCR value calculation
func (m Measurement) IsFake() bool {
	return m.ID.IsFake()
}

// NoHash forces to skip hashing of this measurement's data during PCR calculation
func (m Measurement) NoHash() bool {
	return m.ID.NoHash()
}

// EventLogEventType returns value of "Type" field of the EventLog entry
// associated with the measurement.
func (m Measurement) EventLogEventType() *tpmeventlog.EventType {
	return m.ID.EventLogEventType()
}

func (m Measurement) String() string {
	b, err := json.Marshal(&m)
	if err != nil {
		panic(err)
	}
	return string(b)
}

// Copy performs a deep copy.
func (m Measurement) Copy() *Measurement {
	if m.Data != nil {
		m.Data = m.Data.Copy()
	}
	return &m
}

// Equal performs a deep comparison of two measurements and returns true if
// they contain exactly the same information.
func (m *Measurement) Equal(cmp *Measurement) bool {
	return reflect.DeepEqual(m, cmp)
}

// CompileMeasurableData returns all the bytes used for a PCR value measurement,
// referenced by `Data` from the image `uefi`.
func (m Measurement) CompileMeasurableData(image []byte) []byte {
	if m.IsFake() {
		return nil
	}

	var result []byte
	for _, chunk := range m.Data {
		fragment := chunk.CompileMeasurableData(image)
		result = append(result, fragment...)
	}
	return result
}

// Ranges returns a slice of all Range-s where ForceData is nil.
func (m Measurement) Ranges() bytes.Ranges {
	return m.Data.Ranges()
}

// Calculate returns the hash from the gathered blocks from image
func (m *Measurement) Calculate(image []byte, hashFunc hash.Hash) ([]byte, error) {
	if m.IsFake() {
		return nil, nil
	}

	data := m.CompileMeasurableData(image)
	if m.NoHash() {
		return data, nil
	}

	_, err := hashFunc.Write(data)
	if err != nil {
		return nil, err
	}

	defer hashFunc.Reset()
	return hashFunc.Sum(nil), nil
}

// NewStaticDataMeasurement returns a measurement of a pre-defined value.
func NewStaticDataMeasurement(id MeasurementID, data []byte) *Measurement {
	return &Measurement{
		ID: id,
		Data: []DataChunk{
			{
				ForceData: data,
			},
		},
	}
}

// NewRangesMeasurement returns a measurement of multiple ranges of the
// firmware image
func NewRangesMeasurement(id MeasurementID, r bytes.Ranges) *Measurement {
	chunks := make([]DataChunk, len(r))
	for idx := range r {
		chunks[idx].Range = r[idx]
	}
	return &Measurement{
		ID:   id,
		Data: chunks,
	}
}

// NewRangeMeasurement returns a measurement of a single range of a firmware
// image
func NewRangeMeasurement(id MeasurementID, offset uint64, length uint64) *Measurement {
	r := bytes.Range{
		Offset: offset,
		Length: length,
	}
	return &Measurement{
		ID: id,
		Data: []DataChunk{
			{
				Range: r,
			},
		},
	}
}

// CachedMeasurement is a Measurement with hash value computed at creation time
type CachedMeasurement struct {
	Measurement
	data []byte
	hash []byte
}

func (m Measurement) Cache(image []byte, hasher hash.Hash) (*CachedMeasurement, error) {
	data := m.CompileMeasurableData(image)
	hash, err := m.Calculate(image, hasher)
	if err != nil {
		return nil, err
	}

	return &CachedMeasurement{m, data, hash}, nil
}

func (m CachedMeasurement) CompileMeasurableData(image []byte) []byte {
	return m.data
}

func (m CachedMeasurement) Calculate(image []byte, hasher hash.Hash) ([]byte, error) {
	return m.hash, nil
}

// Measurements is multiple Measurements.
// The order is important: PCR value will be calculated using the
// order this slice have (it won't be sorted in any way to do the calculation).
type Measurements []*Measurement

// AddOffset adds offset to all `Offset`-s of all ranges of all measurements.
//
// This could be used if the measurements are used against of a part of an
// UEFI image (instead of the whole image).
func (s Measurements) AddOffset(offset int64) {
	for measurementIdx := range s {
		if s[measurementIdx] == nil {
			continue
		}
		for dataIdx := range s[measurementIdx].Data {
			data := &s[measurementIdx].Data[dataIdx]
			if data.Range.Length == 0 {
				continue
			}
			data.Range.Offset = uint64(int64(data.Range.Offset) + offset)
		}
	}
}

// Find returns the first measurement with the specified MeasurementID.
// Or returns nil, if such measurement was not found.
func (s Measurements) Find(id MeasurementID) *Measurement {
	for _, measurement := range s {
		if measurement.ID == id {
			return measurement
		}
	}

	return nil
}

// Copy performs a deep copy.
func (s Measurements) Copy() Measurements {
	if s == nil {
		return nil
	}

	c := make(Measurements, 0, len(s))
	for _, m := range s {
		c = append(c, m.Copy())
	}
	return c
}

// Data returns all the data chunks of all measurements
func (s Measurements) Data() DataChunks {
	var result []DataChunk
	for _, measurement := range s {
		if measurement == nil {
			continue
		}
		result = append(result, measurement.Data...)
	}
	return result
}

// Ranges returns a slice of all Range-s where ForceData is nil.
func (s Measurements) Ranges() bytes.Ranges {
	return s.Data().Ranges()
}

// CompileMeasurableData returns all the bytes used for a PCR value measurement,
// references by all measurements of `s` from the image `uefi`.
func (s Measurements) CompileMeasurableData(image []byte) []byte {
	var result []byte
	for _, measurement := range s {
		result = append(result, measurement.CompileMeasurableData(image)...)
	}
	return result
}

// FindOverlapping returns those measurements which overlaps with byte range
// `byteRange`.
func (s Measurements) FindOverlapping(byteRange bytes.Range) Measurements {
	result := Measurements{}

	for _, measurement := range s {
		if measurement == nil {
			continue
		}
		for _, chunk := range measurement.Data {
			if byteRange.Intersect(chunk.Range) {
				result = append(result, measurement)
				break // breaks only the inner `for`
			}
		}
	}

	return result
}

// Printfer requires a method with signature of a standard Printf.
type Printfer interface {
	Printf(fmt string, args ...interface{})
}

// Calculate [deprecated since 1jul2021] performs the calculation of the PCR value using image `uefi`.
func (s Measurements) Calculate(image []byte, initialValue uint8, hashFunc hash.Hash, logger Printfer) []byte {
	mes := make([]MeasureEvent, len(s))
	for i := range s {
		mes[i] = s[i]
	}

	hash, err := CalculatePCR(image, initialValue, mes, hashFunc, logger)
	if err != nil {
		panic(err)
	}
	return hash
}

// CalculatePCR performs the calculation of the PCR value using image `uefi`.
func CalculatePCR(image []byte, initialValue uint8, measureEvents []MeasureEvent, hasher hash.Hash, logger Printfer) ([]byte, error) {
	result := make([]byte, hasher.Size())
	result[len(result)-1] = initialValue
	if logger != nil {
		logger.Printf("Set 0x -> 0x%X\n\n", result)
	}

	for _, m := range measureEvents {
		hash, err := m.Calculate(image, hasher)
		if err != nil {
			return nil, err
		}
		if hash == nil {
			continue
		}

		if logger != nil {
			data := m.CompileMeasurableData(image)
			if uint(len(data)) > LoggingDataLimit {
				logger.Printf("Event '%s': %x... (len: %d) (%T)\n", m.GetID(), data[:LoggingDataLimit], len(data), hasher)
			} else {
				logger.Printf("Event '%s': %x (%T)\n", m.GetID(), data, hasher)
			}
		}

		_, err = hasher.Write(result)
		if err != nil {
			return nil, err
		}

		_, err = hasher.Write(hash)
		if err != nil {
			return nil, err
		}

		oldResult := result
		result = hasher.Sum(nil)
		hasher.Reset()
		if logger != nil {
			logger.Printf("%T(0x %X %X) == 0x%X\n\n", hasher, oldResult, hash, result)
		}
	}
	return result, nil
}
