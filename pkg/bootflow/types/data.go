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

// RawBytes are the initial (not yet hashed or converted other way) bytes.
type RawBytes []byte

// RawBytes implements RawBytesGetter.
func (b RawBytes) RawBytes() RawBytes {
	return b
}

// ConvertBy converts the bytes to final bytes given a DataConverter.
func (b RawBytes) ConvertBy(c DataConverter) ConvertedBytes {
	if c == nil {
		return ConvertedBytes(b)
	}
	return c.Convert(b)
}

// RawBytesGetter is an abstract source of RawBytes.
type RawBytesGetter interface {
	RawBytes() RawBytes
}

// ConvertedBytes is the final representation of bytes (for example
// a digest to be extended to a PCR).
type ConvertedBytes []byte

// String implements fmt.Stringer.
func (d ConvertedBytes) String() string {
	return fmt.Sprintf("0x%X", []byte(d))
}

// UnionForcedBytesOrReference is an union of ForcedBytes and a Reference.
// Go does not support union-s, so a `struct` is used here instead.
//
// If `ForcedBytes` is not-nil then `ForcedBytes` is used, otherwise `Reference`.
type UnionForcedBytesOrReference struct {
	ForcedBytes RawBytes
	Reference   *Reference
}

// Value returns the value stored in union `ForcedBytesOrReference`.
//
// It then can be type-switched as `[]byte` and `Reference`.
func (u *UnionForcedBytesOrReference) Value() RawBytesGetter {
	if u.ForcedBytes == nil {
		return u.Reference
	}
	if u.Reference != nil {
		panic("UnionForcedBytesOrReference is supposed to be an union, but both ForcedBytes and Reference are set")
	}
	return u.ForcedBytes
}

// String implements fmt.Stringer.
func (u UnionForcedBytesOrReference) String() string {
	if u.ForcedBytes != nil {
		return fmt.Sprintf("{ForcedBytes: 0x%X}", u.ForcedBytes)
	}
	return fmt.Sprintf("{Ref: %s}", u.Reference.String())
}

// RawBytes implements RawBytesGetter.
func (u *UnionForcedBytesOrReference) RawBytes() RawBytes {
	return u.Value().RawBytes()
}

// UnionForcedBytesOrReferences is a slice of unions 'UnionForcedBytesOrReference'.
type UnionForcedBytesOrReferences []UnionForcedBytesOrReference

// RawBytes concatenates all RawBytes values together.
func (s UnionForcedBytesOrReferences) RawBytes() RawBytes {
	var result RawBytes
	for _, u := range s {
		result = append(result, u.RawBytes()...)
	}
	return result
}

// ForcedBytes concatenates all ForcedByte values together.
func (s UnionForcedBytesOrReferences) ForcedBytes() RawBytes {
	size := 0
	isSet := false
	for _, u := range s {
		size += len(u.ForcedBytes)
		isSet = isSet || u.ForcedBytes != nil
	}
	if !isSet {
		return nil
	}
	result := make([]byte, size)
	ptr := result
	for _, u := range s {
		copy(ptr, u.ForcedBytes)
		ptr = ptr[len(u.ForcedBytes):]
	}
	return result
}

// References returns all references.
func (s UnionForcedBytesOrReferences) References() References {
	var result References
	for _, u := range s {
		if u.ForcedBytes != nil {
			continue
		}
		result = append(result, *u.Reference)
	}
	return result
}

// String implements fmt.Stringer.
func (s UnionForcedBytesOrReferences) String() string {
	if len(s) == 0 {
		return "{}"
	}

	if s.ForcedBytes() == nil {
		return fmt.Sprintf("{Refs: %s}", s.References())
	}
	if s.References() == nil {
		return fmt.Sprintf("{ForcedBytes: 0x%X}", s.ForcedBytes())
	}

	var result strings.Builder
	result.WriteRune('[')
	for idx, u := range s {
		if idx != 0 {
			result.WriteString(", ")
		}
		result.WriteString(u.String())
	}
	result.WriteRune(']')
	return result.String()
}

// Data is byte-data (given directly or by a reference to a SystemArtifact).
type Data struct {
	UnionForcedBytesOrReferences
	Converter DataConverter `faker:"data_converter"`
}

func NewForcedData(b RawBytes) *Data {
	return &Data{
		UnionForcedBytesOrReferences: []UnionForcedBytesOrReference{{
			ForcedBytes: b,
		}},
	}
}

func NewReferenceData(ref *Reference) *Data {
	return &Data{
		UnionForcedBytesOrReferences: []UnionForcedBytesOrReference{{
			Reference: ref,
		}},
	}
}

func NewReferencesData(refs References) *Data {
	var result UnionForcedBytesOrReferences
	for idx := range refs {
		result = append(result, UnionForcedBytesOrReference{
			Reference: &refs[idx],
		})
	}
	return &Data{
		UnionForcedBytesOrReferences: result,
	}
}

// ConvertedBytes returns the final/converted bytes defined by Data.
func (d *Data) ConvertedBytes() []byte {
	return d.RawBytes().ConvertBy(d.Converter)
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

// BySystemArtifact filters references to only those, who refers to the given SystemArtifact.
func (s References) BySystemArtifact(sa SystemArtifact) References {
	var result References
	for _, ref := range s {
		if ref.Artifact == sa {
			result = append(result, ref)
		}
	}
	return result
}

// Ranges concatenates and returns all Ranges together.
func (s References) Ranges() pkgbytes.Ranges {
	var result pkgbytes.Ranges
	for _, r := range s {
		result = append(result, r.Ranges...)
	}
	return result
}

// Resolve uses AddressMapper-s to resolve addresses to final references.
//
// On success: all AddressMappers will be nil and all Ranges will reference
// to the actual ranges of the data. On failure an error returned, but
// some References might be already resolved.
func (s References) Resolve() error {
	for idx := range s {
		ref := &s[idx]
		if ref.AddressMapper == nil {
			continue
		}
		ranges, err := ref.AddressMapper.Resolve(ref.Artifact, ref.Ranges...)
		if err != nil {
			return fmt.Errorf("unable to resolve reference#%d:%s: %w", idx, format.NiceString(ref), err)
		}
		ref.Ranges = ranges
		ref.AddressMapper = nil
	}
	return nil
}

// SortAndMerge sorts References and merges those which touch or overlap.
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
func (s References) RawBytes() RawBytes {
	var buf bytes.Buffer
	for _, ref := range s {
		if _, err := buf.Write(ref.RawBytes()); err != nil {
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
	Artifact      SystemArtifact `faker:"system_artifact"`
	AddressMapper AddressMapper  `faker:"address_mapper"`
	Ranges        pkgbytes.Ranges
}

// ResolvedRanges returns Ranges, already resolved using AddressMapper.
func (ref *Reference) ResolvedRanges() (pkgbytes.Ranges, error) {
	if ref.AddressMapper == nil {
		return ref.Ranges, nil
	}
	return ref.AddressMapper.Resolve(ref.Artifact, ref.Ranges...)
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

// RawBytes returns the bytes data referenced by the Reference.
func (ref *Reference) RawBytes() RawBytes {
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
		for _, mr := range mappedRanges {
			n, err := ref.Artifact.ReadAt(result[curPos:curPos+mr.Length], int64(mr.Offset))
			if err != nil && n != int(mr.Length) {
				panic(fmt.Errorf("artifact %T, range %X:%X (orig: %X:%X), n: %X, error: %w", ref.Artifact, mr.Offset, mr.End(), r.Offset, r.End(), n, err))
			}
			curPos += mr.Length
			if n != int(mr.Length) {
				panic(fmt.Errorf("unexpected read size: expected:%d actual:%d on range %#+v", mr.Length, n, mr))
			}
		}
	}
	return result
}

// MeasuredData is a piece of Data which was measured by any of TrustChain-s.
type MeasuredData struct {
	Data
	DataSource DataSource `faker:"data_source"`
	Actor      Actor      `faker:"actor"`
	Action     Action     `faker:"action"`
	TrustChain TrustChain `faker:"trust_chain"`
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

// References returns all References.
func (s MeasuredDataSlice) References() References {
	var result References
	for _, d := range s {
		result = append(result, d.References()...)
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
