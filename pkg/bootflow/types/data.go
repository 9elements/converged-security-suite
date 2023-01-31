package types

import (
	"bytes"
	"fmt"
	"strings"

	pkgbytes "github.com/linuxboot/fiano/pkg/bytes"
)

// Data is byte-data (given directly or by a reference to a SystemArtifact).
type Data struct {
	ForceBytes []byte
	References References
	Converter  DataConverter

	IsMeasurementOf References
}

// String implements fmt.Stringer.
func (d Data) String() string {
	if d.ForceBytes != nil {
		return fmt.Sprintf("{ForceBytes: %X}", d.ForceBytes)
	}
	return fmt.Sprintf("{Refs: %v}", d.References)
}

func (d *Data) RawBytes() []byte {
	if d.ForceBytes != nil && d.References != nil {
		panic("Data is supposed to be used as union")
	}
	if d.ForceBytes != nil {
		return d.ForceBytes
	}
	return d.References.Bytes()
}

// Bytes returns the bytes defined by Data.
func (d *Data) Bytes() []byte {
	b := d.RawBytes()
	if d.Converter == nil {
		return b
	}

	return d.Converter.Convert(b)
}

// References is a a slice of Reference-s.
type References []Reference

// Bytes returns a concatenation of data of all the referenced byte ranges.
func (s References) Bytes() []byte {
	var buf bytes.Buffer
	for _, ref := range s {
		if _, err := buf.Write(ref.Bytes()); err != nil {
			panic(err)
		}
	}
	return buf.Bytes()
}

// AddressMapper maps an address. If is an untyped nil then address should be mapped to itself
// by the consumer of this interface.
type AddressMapper interface {
	Resolve(SystemArtifact, pkgbytes.Range) (pkgbytes.Ranges, error)
}

// Reference is a reference to a bytes data in a SystemArtifact.
type Reference struct {
	Artifact      SystemArtifact
	AddressMapper AddressMapper
	Ranges        pkgbytes.Ranges
}

// String implements fmt.Stringer()
func (ref Reference) String() string {
	artifactType := fmt.Sprintf("%T", ref.Artifact)
	if idx := strings.Index(artifactType, "."); idx >= 0 {
		artifactType = artifactType[idx+1:]
	}
	return fmt.Sprintf("%s:%v", artifactType, ref.Ranges)
}

// Bytes returns the bytes data referenced by the Reference.
func (ref *Reference) Bytes() []byte {
	totalLength := uint64(0)
	ranges := ref.Ranges
	ranges.SortAndMerge()
	for _, r := range ranges {
		totalLength += r.Length
	}

	result := make([]byte, totalLength)
	curPos := uint64(0)
	for _, r := range ranges {
		mappedRanges := pkgbytes.Ranges{r}
		if ref.AddressMapper != nil {
			var err error
			mappedRanges, err = ref.AddressMapper.Resolve(ref.Artifact, r)
			if err != nil {
				panic(err)
			}
		}
		for _, r := range mappedRanges {
			n, err := ref.Artifact.ReadAt(result[curPos:curPos+r.Length], int64(r.Offset))
			if err != nil {
				panic(err)
			}
			curPos += r.Length
			if n != int(r.Length) {
				panic(fmt.Errorf("unexpected read size: expected:%d actual:%d", r.Length, n))
			}
		}
	}
	return result
}

// MeasuredData is a piece of Data which was measured by any of TrustChain-s.
type MeasuredData struct {
	Data
	DataSource DataSource
	Actor      Actor
	TrustChain TrustChain
}

// String implements fmt.Stringer.
func (d MeasuredData) String() string {
	var result strings.Builder
	result.WriteString(fmt.Sprintf("%s <- %v", typeMapKey(d.TrustChain).Name(), d.Data))
	if d.DataSource != nil {
		result.WriteString(fmt.Sprintf(" (%v)", d.DataSource))
	}
	if d.Actor != nil {
		result.WriteString(fmt.Sprintf(" [%T]", d.Actor))
	}
	return result.String()
}

// MeasuredDataSlice is a slice of MeasuredData-s.
type MeasuredDataSlice []MeasuredData

// String implements fmt.Stringer.
func (s MeasuredDataSlice) String() string {
	var result strings.Builder
	for idx, data := range s {
		fmt.Fprintf(&result, "%d. %s\n", idx, data.String())
	}
	return result.String()
}
