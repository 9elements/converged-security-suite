package types

// TrustChain is a SubSystem responsible for maintaining a chain of trust.
//
// Examples: TPM-backed measured boot, DICE-backed measured boot, Signatures-backed verified boot, etc.
type TrustChain interface {
	SubSystem
}
