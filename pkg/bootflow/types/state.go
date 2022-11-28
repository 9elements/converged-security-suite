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

	SystemArtifacts          SystemArtifacts
	TrustChains              TrustChains
	CurrentActor             Actor
	CurrentActionCoordinates ActionCoordinates
	MeasuredData             []MeasuredData
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
	state.CurrentActionCoordinates.Flow = flow
	state.CurrentActionCoordinates.StepIndex = stepIdx
	state.CurrentActionCoordinates.ActionIndex = 0
}

func (state *State) GetCurrentActionCoordinates() ActionCoordinates {
	return state.CurrentActionCoordinates
}

// GetTrustChainByTypeFromState extracts a specific TrustChain given its type.
//
// This was supposed to be a method of `*State`, but Go does not support generic
// methods, so it is a free function.
func GetTrustChainByTypeFromState[T TrustChain](
	state *State,
) (T, error) {
	var sample T
	key := typeMapKey(sample)
	value, ok := state.TrustChains[key].(T)
	if !ok {
		return value, ErrNoTrustChain{TrustChainKey: key}
	}
	return value, nil
}

// WithTrustChain extracts a specific TrustChain given its type.
//
// This was supposed to be a method of `*State`, but Go does not support generic
// methods, so it is a free function.
func WithTrustChain[TC TrustChain](
	state *State,
	callback func(trustChain TC) error,
) error {
	trustChain, err := GetTrustChainByTypeFromState[TC](state)
	if err != nil {
		return err
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

// SystemArtifactExec extracts a specific SystemArtifact given its type.
//
// This was supposed to be a method of `*State`, but Go does not support generic
// methods, so it is a free function.
func GetSystemArtifactByTypeFromState[SA SystemArtifact](
	state *State,
) (SA, error) {
	var sample SA
	key := typeMapKey(sample)
	systemArtifact, ok := state.SystemArtifacts[key].(SA)
	if !ok {
		return systemArtifact, ErrNoSystemArtifact{SystemArtifactKey: key}
	}

	return systemArtifact, nil
}

// WithSystemArtifact extracts a specific SystemArtifact given its type.
//
// This was supposed to be a method of `*State`, but Go does not support generic
// methods, so it is a free function.
func WithSystemArtifact[SA SystemArtifact](
	state *State,
	callback func(trustChain SA) error,
) error {
	systemArtifact, err := GetSystemArtifactByTypeFromState[SA](state)
	if err != nil {
		return err
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
		Actor:      state.CurrentActor,
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
	if len(state.CurrentActionCoordinates.Flow) > 0 {
		fmt.Fprintf(&result, "CurrentFlow:\n\t%s\n", nestedGoStringOf(state.CurrentActionCoordinates.Flow))
		fmt.Fprintf(&result, "CurrentStepIndex: %d\n", state.CurrentActionCoordinates.StepIndex)
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
