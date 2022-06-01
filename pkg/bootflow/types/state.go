package types

import (
	"fmt"
	"reflect"
	"strings"
)

// State describes a virtual state of a machine being booted
type State struct {
	// Do not mutate these values from the outside, the mutability
	// is owned by State itself.

	SystemArtifacts SystemArtifacts
	TrustChains     TrustChains
	CurrentFlow     Flow
	CurrentStepIdx  uint
	VerifiedData    []VerifiedData
}

func typeMapKey(i interface{}) reflect.Type {
	k := reflect.TypeOf(i)
	for k.Kind() == reflect.Ptr {
		k = k.Elem()
	}
	return k
}

func NewState() *State {
	return &State{
		SystemArtifacts: map[reflect.Type]SystemArtifact{},
		TrustChains:     map[reflect.Type]TrustChain{},
	}
}

func (state *State) SetFlow(flow Flow, stepIdx uint) {
	state.CurrentFlow = flow
	state.CurrentStepIdx = stepIdx
}

func (state *State) TrustChainExec(
	trustChainSample TrustChain,
	callback func(trustChain TrustChain) error,
) error {
	key := typeMapKey(trustChainSample)
	trustChain := state.TrustChains[key]
	if trustChain == nil {
		return ErrNoTrustChain{TrustChainKey: key}
	}

	return callback(trustChain)
}

func (state *State) EnableTrustChain(trustChain TrustChain) {
	if reflect.TypeOf(trustChain).Kind() != reflect.Ptr {
		panic(fmt.Sprintf("%T is not a modifiable type", trustChain))
	}

	k := typeMapKey(trustChain)
	if _, ok := state.TrustChains[k]; ok {
		panic(fmt.Sprintf("double-setting of the same trust chain type: %s", k))
	}
	state.TrustChains[k] = trustChain
}

func (state *State) SystemArtifactExec(
	systemArtifactSample SystemArtifact,
	callback func(systemArtifact SystemArtifact) error,
) error {
	key := typeMapKey(systemArtifactSample)
	systemArtifact := state.SystemArtifacts[key]
	if systemArtifact == nil {
		return ErrNoSystemArtifact{SystemArtifactKey: key}
	}

	return callback(systemArtifact)
}

func (state *State) EnableSystemArtifact(systemArtifact SystemArtifact) {
	if reflect.TypeOf(systemArtifact).Kind() != reflect.Ptr {
		panic(fmt.Sprintf("%T is not a modifiable type", systemArtifact))
	}

	k := typeMapKey(systemArtifact)
	if _, ok := state.SystemArtifacts[k]; ok {
		panic(fmt.Sprintf("double-setting of the same system artifact type: %s", k))
	}
	state.SystemArtifacts[k] = systemArtifact
}

func (state *State) AddVerifiedData(trustChain TrustChain, data Data) {
	state.VerifiedData = append(state.VerifiedData, VerifiedData{
		Data:       data,
		TrustChain: trustChain,
	})
}

func (state *State) GoString() string {
	var result strings.Builder
	if len(state.SystemArtifacts) > 0 {
		fmt.Fprintf(&result, "SystemArtifacts:\n\t%s\n", nestedGoStringOf(state.SystemArtifacts))
	}
	if len(state.TrustChains) > 0 {
		fmt.Fprintf(&result, "TrustChains:\n\t%s\n", nestedGoStringOf(state.TrustChains))
	}
	if len(state.CurrentFlow) > 0 {
		fmt.Fprintf(&result, "CurrentFlow:\n\t%s\n", nestedGoStringOf(state.CurrentFlow))
		fmt.Fprintf(&result, "CurrentStepIndex: %d\n", state.CurrentStepIdx)
	}
	if len(state.VerifiedData) > 0 {
		fmt.Fprintf(&result, "VerifiedData:\n\t%s\n", nestedGoStringOf(state.VerifiedData))
	}
	return result.String()
}

func (state *State) GetVerifiedDataBy(trustChainSample TrustChain) []VerifiedData {
	var result []VerifiedData
	cmpKey := typeMapKey(trustChainSample)
	for _, verifiedData := range state.VerifiedData {
		if typeMapKey(verifiedData.TrustChain) == cmpKey {
			result = append(result, verifiedData)
		}
	}
	return result
}
