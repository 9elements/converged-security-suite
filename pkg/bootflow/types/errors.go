package types

import (
	"fmt"
	"reflect"
)

type ErrNoTrustChain struct {
	TrustChainKey reflect.Type
}

func (err ErrNoTrustChain) Error() string {
	return fmt.Sprintf("no trust chain of type %T found", err.TrustChainKey)
}

func (err ErrNoTrustChain) TrustChainTypeIs(sample TrustChain) bool {
	return err.TrustChainKey == typeMapKey(sample)
}

func (err ErrNoTrustChain) String() string {
	return fmt.Sprintf("ErrNoTrustChain{%s}", err.TrustChainKey.Name())
}

type ErrNoSystemArtifact struct {
	SystemArtifactKey reflect.Type
}

func (err ErrNoSystemArtifact) Error() string {
	return fmt.Sprintf("no system artifact of type %T found", err.SystemArtifactKey)
}

func (err ErrNoSystemArtifact) ErrNoSystemArtifactTypeIs(sample SystemArtifact) bool {
	return err.SystemArtifactKey == typeMapKey(sample)
}

func (err ErrNoSystemArtifact) String() string {
	return fmt.Sprintf("ErrNoSystemArtifact{%s}", err.SystemArtifactKey.Name())
}
