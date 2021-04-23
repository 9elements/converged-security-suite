//go:generate manifestcodegen

package bootpolicy

import "github.com/9elements/converged-security-suite/v2/pkg/provisioning/bootguard/common"

// Signature contains the signature of the BPM.
type Signature struct {
	StructInfo          `id:"__PMSG__" version:"0x10"`
	common.KeySignature `json:"sigKeySignature"`
}
