//go:generate manifestcodegen

package bootpolicy

type PM struct {
	StructInfo `id:"__PMDA__" version:"0x10"`
	Data       []byte `json:"pcData"`
}
