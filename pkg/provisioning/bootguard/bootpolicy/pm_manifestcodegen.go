// +build !manifestcodegen
// Code generated by "menifestcodegen". DO NOT EDIT.
// To reproduce: go run github.com/9elements/converged-security-suite/v2/pkg/intel/metadata/manifest/common/manifestcodegen/cmd/manifestcodegen github.com/9elements/converged-security-suite/v2/pkg/intel/metadata/manifest/bootpolicy

package bootpolicy

import (
	"encoding/binary"
	"fmt"
	"io"
	"strings"

	"github.com/9elements/converged-security-suite/v2/pkg/intel/metadata/manifest/common/pretty"
	"github.com/9elements/converged-security-suite/v2/pkg/provisioning/bootguard/common"
)

var (
	// Just to avoid errors in "import" above in case if it wasn't used below
	_ = binary.LittleEndian
	_ = (fmt.Stringer)(nil)
	_ = (io.Reader)(nil)
	_ = pretty.Header
	_ = strings.Join
	_ = common.StructInfo{}
)

// NewPM returns a new instance of PM with
// all default values set.
func NewPM() *PM {
	s := &PM{}
	copy(s.StructInfo.ID[:], []byte(StructureIDPM))
	s.StructInfo.Version = 0x10
	s.Rehash()
	return s
}

// StructureIDPM is the StructureID (in terms of
// the document #575623) of element 'PM'.
const StructureIDPM = "__PMDA__"

// GetStructInfo returns current value of StructInfo of the structure.
//
// StructInfo is a set of standard fields with presented in any element
// ("element" in terms of document #575623).
func (s *PM) GetStructInfo() common.StructInfo {
	return s.StructInfo
}

// SetStructInfo sets new value of StructInfo to the structure.
//
// StructInfo is a set of standard fields with presented in any element
// ("element" in terms of document #575623).
func (s *PM) SetStructInfo(newStructInfo common.StructInfo) {
	s.StructInfo = newStructInfo
}

// ReadFrom reads the PM from 'r' in format defined in the document #575623.
func (s *PM) ReadFrom(r io.Reader) (int64, error) {
	var totalN int64

	err := binary.Read(r, binary.LittleEndian, &s.StructInfo)
	if err != nil {
		return totalN, fmt.Errorf("unable to read structure info at %d: %w", totalN, err)
	}
	totalN += int64(binary.Size(s.StructInfo))

	n, err := s.ReadDataFrom(r)
	if err != nil {
		return totalN, fmt.Errorf("unable to read data: %w", err)
	}
	totalN += n

	return totalN, nil
}

// ReadDataFrom reads the PM from 'r' excluding StructInfo,
// in format defined in the document #575623.
func (s *PM) ReadDataFrom(r io.Reader) (int64, error) {
	totalN := int64(0)

	// StructInfo (ManifestFieldType: structInfo)
	{
		// ReadDataFrom does not read Struct, use ReadFrom for that.
	}

	// Data (ManifestFieldType: arrayDynamic)
	{
		var size uint16
		err := binary.Read(r, binary.LittleEndian, &size)
		if err != nil {
			return totalN, fmt.Errorf("unable to the read size of field 'Data': %w", err)
		}
		totalN += int64(binary.Size(size))
		s.Data = make([]byte, size)
		n, err := len(s.Data), binary.Read(r, binary.LittleEndian, s.Data)
		if err != nil {
			return totalN, fmt.Errorf("unable to read field 'Data': %w", err)
		}
		totalN += int64(n)
	}

	return totalN, nil
}

// RehashRecursive calls Rehash (see below) recursively.
func (s *PM) RehashRecursive() {
	s.StructInfo.Rehash()
	s.Rehash()
}

// Rehash sets values which are calculated automatically depending on the rest
// data. It is usually about the total size field of an element.
func (s *PM) Rehash() {

}

// WriteTo writes the PM into 'w' in format defined in
// the document #575623.
func (s *PM) WriteTo(w io.Writer) (int64, error) {
	totalN := int64(0)
	s.Rehash()

	// StructInfo (ManifestFieldType: structInfo)
	{
		n, err := s.StructInfo.WriteTo(w)
		if err != nil {
			return totalN, fmt.Errorf("unable to write field 'StructInfo': %w", err)
		}
		totalN += int64(n)
	}

	// Data (ManifestFieldType: arrayDynamic)
	{
		size := uint16(len(s.Data))
		err := binary.Write(w, binary.LittleEndian, size)
		if err != nil {
			return totalN, fmt.Errorf("unable to write the size of field 'Data': %w", err)
		}
		totalN += int64(binary.Size(size))
		n, err := len(s.Data), binary.Write(w, binary.LittleEndian, s.Data)
		if err != nil {
			return totalN, fmt.Errorf("unable to write field 'Data': %w", err)
		}
		totalN += int64(n)
	}

	return totalN, nil
}

// StructInfoSize returns the size in bytes of the value of field StructInfo
func (s *PM) StructInfoTotalSize() uint64 {
	return s.StructInfo.TotalSize()
}

// DataSize returns the size in bytes of the value of field Data
func (s *PM) DataTotalSize() uint64 {
	size := uint64(binary.Size(uint16(0)))
	size += uint64(len(s.Data))
	return size
}

// StructInfoOffset returns the offset in bytes of field StructInfo
func (s *PM) StructInfoOffset() uint64 {
	return 0
}

// DataOffset returns the offset in bytes of field Data
func (s *PM) DataOffset() uint64 {
	return s.StructInfoOffset() + s.StructInfoTotalSize()
}

// Size returns the total size of the PM.
func (s *PM) TotalSize() uint64 {
	if s == nil {
		return 0
	}

	var size uint64
	size += s.StructInfoTotalSize()
	size += s.DataTotalSize()
	return size
}

// PrettyString returns the content of the structure in an easy-to-read format.
func (s *PM) PrettyString(depth uint, withHeader bool, opts ...pretty.Option) string {
	var lines []string
	if withHeader {
		lines = append(lines, pretty.Header(depth, "PM", s))
	}
	if s == nil {
		return strings.Join(lines, "\n")
	}
	// ManifestFieldType is structInfo
	lines = append(lines, pretty.SubValue(depth+1, "Struct Info", "", &s.StructInfo, opts...)...)
	// ManifestFieldType is arrayDynamic
	lines = append(lines, pretty.SubValue(depth+1, "Data", "", &s.Data, opts...)...)
	if depth < 2 {
		lines = append(lines, "")
	}
	return strings.Join(lines, "\n")
}
