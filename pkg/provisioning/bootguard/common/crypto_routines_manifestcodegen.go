// +build !manifestcodegen
// Code generated by "menifestcodegen". DO NOT EDIT.
// To reproduce: go run github.com/9elements/converged-security-suite/v2/pkg/intel/metadata/manifest/common/manifestcodegen/cmd/manifestcodegen github.com/9elements/converged-security-suite/v2/pkg/intel/metadata/manifest

package common

import (
	"encoding/binary"
	"fmt"
	"io"
	"strings"

	"github.com/9elements/converged-security-suite/v2/pkg/intel/metadata/manifest/common/pretty"
)

var (
	// Just to avoid errors in "import" above in case if it wasn't used below
	_ = binary.LittleEndian
	_ = (fmt.Stringer)(nil)
	_ = (io.Reader)(nil)
	_ = pretty.Header
	_ = strings.Join
)

// PrettyString returns the bits of the flags in an easy-to-read format.
func (v Algorithm) PrettyString(depth uint, withHeader bool, opts ...pretty.Option) string {
	return v.String()
}

// TotalSize returns the total size measured through binary.Size.
func (v Algorithm) TotalSize() uint64 {
	return uint64(binary.Size(v))
}

// WriteTo writes the Algorithm into 'w' in binary format.
func (v Algorithm) WriteTo(w io.Writer) (int64, error) {
	return int64(v.TotalSize()), binary.Write(w, binary.LittleEndian, v)
}

// ReadFrom reads the Algorithm from 'r' in binary format.
func (v Algorithm) ReadFrom(r io.Reader) (int64, error) {
	return int64(v.TotalSize()), binary.Read(r, binary.LittleEndian, v)
}
