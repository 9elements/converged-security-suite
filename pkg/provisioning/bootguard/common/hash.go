//go:generate manifestcodegen

package common

// HashStructure describes a digest.
type HashStructure struct {
	HashAlg    Algorithm `default:"0x10" json:"hsAlg"`
	HashBuffer []byte    `json:"hsBuffer"`
}
