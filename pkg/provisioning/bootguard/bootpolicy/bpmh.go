//go:generate manifestcodegen

package bootpolicy

import "github.com/9elements/converged-security-suite/v2/pkg/provisioning/bootguard/common"

type BPMH struct {
	StructInfo `id:"__ACBP__" version:"0x10"`

	HdrStructVersion uint8 `json:"HdrStructVersion"`

	PMBPMVersion uint8 `json:"bpmhRevision"`

	// PrettyString: BPM SVN
	BPMSVN common.SVN `json:"bpmhSNV"`
	// PrettyString: ACM SVN Auth
	ACMSVNAuth common.SVN `json:"bpmhACMSVN"`

	Reserved0 [1]byte `require:"0" json:"bpmhReserved0,omitemtpy"`

	NEMDataStack Size4K `json:"bpmhNEMStackSize"`
}

// Size4K is a size in units of 4096 bytes.
type Size4K uint16

// InBytes returns the size in bytes.
func (s Size4K) InBytes() uint32 {
	return uint32(s) * 4096
}

// NewSize4K returns the given size as multiple of 4K
func NewSize4K(size uint32) Size4K {
	return Size4K(size / 4096)
}
