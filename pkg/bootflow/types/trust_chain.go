package types

type TrustChains []TrustChain

type TrustChain interface {
	IsInitialized() bool
}
