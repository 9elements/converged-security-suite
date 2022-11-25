package types

import (
	"fmt"
	"reflect"
	"strings"
)

// State describes a virtual state of a machine being booted
type State struct {
	// Do not mutate these fields from the outside, the mutability
	// is owned by State itself.

	SystemArtifacts SystemArtifacts
	TrustChains     TrustChains
	CurrentFlow     Flow
	CurrentStepIdx  uint
	MeasuredData    []MeasuredData
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

// GetTrustChainByTypeFromState extracts a specific TrustChain given its type
// (through the sample).
//
// This was supposed to be a method of `*State`, but Go does not support generic
// methods, so it is a free function.
func GetTrustChainByTypeFromState[T TrustChain](
	state *State,
	sample T,
) (T, error) {
	key := typeMapKey(sample)
	value, ok := state.TrustChains[key].(T)
	if !ok {
		return value, ErrNoTrustChain{TrustChainKey: key}
	}
	return value, nil
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

func (state *State) IncludeTrustChain(trustChain TrustChain) {
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

func (state *State) IncludeSystemArtifact(systemArtifact SystemArtifact) {
	if reflect.TypeOf(systemArtifact).Kind() != reflect.Ptr {
		panic(fmt.Sprintf("%T is not a modifiable type", systemArtifact))
	}

	k := typeMapKey(systemArtifact)
	if _, ok := state.SystemArtifacts[k]; ok {
		panic(fmt.Sprintf("double-setting of the same system artifact type: %s", k))
	}
	state.SystemArtifacts[k] = systemArtifact
}

func (state *State) AddMeasuredData(trustChain TrustChain, data Data) {
	state.MeasuredData = append(state.MeasuredData, MeasuredData{
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
	if len(state.MeasuredData) > 0 {
		fmt.Fprintf(&result, "MeasuredData:\n\t%s\n", nestedGoStringOf(state.MeasuredData))
	}
	return result.String()
}

func (state *State) GetMeasuredDataBy(trustChainSample TrustChain) []MeasuredData {
	var result []MeasuredData
	cmpKey := typeMapKey(trustChainSample)
	for _, measuredData := range state.MeasuredData {
		if typeMapKey(measuredData.TrustChain) == cmpKey {
			result = append(result, measuredData)
		}
	}
	return result
}
