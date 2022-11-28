package types

import (
	"bytes"
	"fmt"
	"strings"

	pkgbytes "github.com/linuxboot/fiano/pkg/bytes"
)

type Data struct {
	ForceBytes []byte
	References References
}

func (d Data) String() string {
	if d.ForceBytes != nil {
		return fmt.Sprintf("{ForceBytes: %X}", d.ForceBytes)
	}
	return fmt.Sprintf("{Refs: %v}", d.References)
}

func (d *Data) Bytes() []byte {
	if d.ForceBytes != nil && d.References != nil {
		panic("Data is supposed to be used as union")
	}
	if d.ForceBytes != nil {
		return d.ForceBytes
	}
	return d.References.Bytes()
}

type References []Reference

func (s References) Bytes() []byte {
	var buf bytes.Buffer
	for _, ref := range s {
		if _, err := buf.Write(ref.Bytes()); err != nil {
			panic(err)
		}
	}
	return buf.Bytes()
}

type Reference struct {
	Artifact SystemArtifact
	Ranges   pkgbytes.Ranges
}

func (ref Reference) String() string {
	artifactType := fmt.Sprintf("%T", ref.Artifact)
	if idx := strings.Index(artifactType, "."); idx >= 0 {
		artifactType = artifactType[idx+1:]
	}
	return fmt.Sprintf("%s:%v", artifactType, ref.Ranges)
}

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
		n, err := ref.Artifact.ReadAt(result[curPos:curPos+r.Length], int64(r.Offset))
		if err != nil {
			panic(err)
		}
		if n != int(r.Length) {
			panic(fmt.Errorf("unexpected read size: expected:%d actual:%d", r.Length, n))
		}
	}
	return result
}

type MeasuredData struct {
	Data
	Actor      Actor
	TrustChain TrustChain
}

func (d MeasuredData) String() string {
	if d.Actor == nil {
		return fmt.Sprintf("%s <- %v", typeMapKey(d.TrustChain).Name(), d.Data)
	}
	return fmt.Sprintf("%s <- %v (%T)", typeMapKey(d.TrustChain).Name(), d.Data, d.Actor)
}

type MeasuredDataSlice []MeasuredData

func (s MeasuredDataSlice) String() string {
	var result strings.Builder
	for idx, data := range s {
		fmt.Fprintf(&result, "%d. %s\n", idx, data.String())
	}
	return result.String()
}
