package types

import (
	"bytes"
	"fmt"
	"sort"
	"strings"
	"sync"

	"github.com/9elements/converged-security-suite/v2/pkg/bootflow/lib/format"
	pkgbytes "github.com/linuxboot/fiano/pkg/bytes"
)

// Data is byte-data (given directly or by a reference to a SystemArtifact).
type Data struct {
	ForceBytes []byte
	References References
	Converter  DataConverter

	IsAlsoMeasurementOf References
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

// MeasuredReferences returns References which are measured/referenced directly or indirectly.
//
// For example if the Data contains a signature, then MeasuredReferences will also return the
// reference to the signed data.
func (d *Data) MeasuredReferences() References {
	result := make(References, len(d.References)+len(d.IsAlsoMeasurementOf))
	copy(result, d.References)
	copy(result[len(d.References):], d.IsAlsoMeasurementOf)
	return result
}

// References is a a slice of Reference-s.
type References []Reference

var (
	objToStringCacheMutex sync.Mutex
	objToStringCache      = map[any]string{}
)

func compareReferenceType(a, b Reference) int {
	// TODO: find less fragile and faster way to order artifacts and address mappers

	objToStringCacheMutex.Lock()
	defer objToStringCacheMutex.Unlock()

	var c0, c1 string
	if a.Artifact != b.Artifact {
		c0, c1 = objToStringCache[a.Artifact], objToStringCache[b.Artifact]
		if c0 == "" {
			c0 = fmt.Sprintf("%T", a.Artifact)
			objToStringCache[a.Artifact] = c0
		}
		if c1 == "" {
			c1 = fmt.Sprintf("%T", b.Artifact)
			objToStringCache[b.Artifact] = c1
		}
		if c0 == c1 {
			panic("the code is written in assumption of one instance per artifact type")
		}
	}
	if a.AddressMapper != a.AddressMapper {
		c0, c1 = objToStringCache[a.AddressMapper], objToStringCache[b.AddressMapper]
		if c0 == "" {
			c0 = fmt.Sprintf("%T", a.AddressMapper)
			objToStringCache[a.AddressMapper] = c0
		}
		if c1 == "" {
			c1 = fmt.Sprintf("%T", b.AddressMapper)
			objToStringCache[b.AddressMapper] = c1
		}
		if c0 == c1 {
			panic("the code is written in assumption of one instance per address mapper type")
		}
	}

	switch {
	case c0 < c1:
		return -1
	case c0 > c1:
		return 1
	default:
		return 0
	}
}

func (s *References) SortAndMerge() {
	if len(*s) < 2 {
		return
	}

	sort.Slice(*s, func(i, j int) bool {
		return compareReferenceType((*s)[i], (*s)[j]) < 0
	})

	for idx := range *s {
		(*s)[idx].Ranges.SortAndMerge()
	}

	var (
		curRef Reference
		outIdx = 0
	)
	for _, ref := range *s {
		if ref.Artifact == curRef.Artifact && ref.AddressMapper == curRef.AddressMapper {
			curRef.Ranges = append(curRef.Ranges, ref.Ranges...)
			continue
		}
		if len(curRef.Ranges) != 0 {
			curRef.Ranges.SortAndMerge()
			(*s)[outIdx] = curRef
			outIdx++
		}
		curRef = ref
	}
	curRef.Ranges.SortAndMerge()
	(*s)[outIdx] = curRef
	outIdx++
	*s = (*s)[:outIdx]
}

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

// Exclude returns the references left after subtracting regions from the provided references.
func (s References) Exclude(exc ...Reference) References {
	if len(s) == 0 {
		return nil
	}

	s0 := make(References, len(s))
	copy(s0, s)
	s0.SortAndMerge()

	s1 := make(References, len(exc))
	copy(s1, exc)
	s1.SortAndMerge()

	var filtered References
	i, j := 0, 0
	for i < len(s0) && j < len(s1) {
		r0 := s0[i]
		r1 := s1[j]
		switch compareReferenceType(r0, r1) {
		case -1:
			filtered = append(filtered, r0)
			i++
		case 1:
			j++
		default:
			var result pkgbytes.Ranges
			for _, r := range r0.Ranges {
				for _, add := range r.Exclude(r1.Ranges...) {
					if add.Length == 0 {
						// TODO: fix this bug in the upstream code
						continue
					}
					result = append(result, add)
				}
			}
			if len(result) > 0 {
				r0.Ranges = result
				filtered = append(filtered, r0)
			}
			i++
			j++
		}
	}
	for ; i < len(s0); i++ {
		filtered = append(filtered, s0[i])
	}

	return filtered
}

// String implements fmt.Stringer
func (s References) String() string {
	var result []string
	for _, ref := range s {
		result = append(result, format.NiceString(ref))
	}
	return strings.Join(result, ", ")
}

// AddressMapper maps an address. If is an untyped nil then address should be mapped to itself
// by the consumer of this interface.
type AddressMapper interface {
	Resolve(SystemArtifact, ...pkgbytes.Range) (pkgbytes.Ranges, error)
	Unresolve(SystemArtifact, ...pkgbytes.Range) (pkgbytes.Ranges, error)
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
	var rangeStrings []string
	for _, r := range ref.Ranges {
		rangeStrings = append(rangeStrings, fmt.Sprintf("%X:%X", r.Offset, r.End()))
	}
	if ref.AddressMapper == nil {
		return fmt.Sprintf(
			"%s:[%s]",
			artifactType,
			strings.Join(rangeStrings, ","),
		)
	}

	addressMapperType := fmt.Sprintf("%T", ref.AddressMapper)
	if idx := strings.Index(addressMapperType, "."); idx >= 0 {
		addressMapperType = addressMapperType[idx+1:]
	}
	return fmt.Sprintf(
		"%s:%s:[%s]",
		artifactType,
		addressMapperType,
		strings.Join(rangeStrings, ","),
	)
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
			if err != nil && n != int(r.Length) {
				panic(fmt.Errorf("artifact %T, range %X:%X, n: %X, error: %w", ref.Artifact, curPos, curPos+r.Length, n, err))
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
	if len(d.IsAlsoMeasurementOf) != 0 {
		result.WriteString(fmt.Sprintf(" <%v>", d.IsAlsoMeasurementOf))
	}
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

// MeasuredReferences returns References which are measured/referenced directly or indirectly.
//
// For example if the Data contains a signature, then MeasuredReferences will also return the
// reference to the signed data.
func (s MeasuredDataSlice) MeasuredReferences() References {
	var result References
	for _, d := range s {
		result = append(result, d.MeasuredReferences()...)
	}
	return result
}

// String implements fmt.Stringer.
func (s MeasuredDataSlice) String() string {
	var result strings.Builder
	for idx, data := range s {
		fmt.Fprintf(&result, "%d. %s\n", idx, data.String())
	}
	return result.String()
}
