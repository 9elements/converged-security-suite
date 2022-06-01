package types

import (
	"fmt"
	"reflect"
	"strings"
)

type TrustChains map[reflect.Type]TrustChain

type TrustChain interface {
	IsInitialized() bool
}

func (m TrustChains) GoString() string {
	var result strings.Builder
	for k, artifact := range m {
		fmt.Fprintf(&result, "%s:\n\t%s\n", k.Name(), nestedGoStringOf(artifact))
	}
	return result.String()
}
