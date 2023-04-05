package types

import (
	"fmt"
	"reflect"
	"strings"
)

// State describes a virtual state of a machine being booted
type State struct {
	// Do not mutate these fields from the outside, the mutability
	// is owned by State itself and BootProcess.

	SystemArtifacts          SystemArtifacts `faker:"system_artifact_map"`
	SubSystems               SubSystems      `faker:"sub_system_map"`
	CurrentActor             Actor           `faker:"actor"`
	CurrentActionCoordinates ActionCoordinates
	CurrentAction            Action `faker:"action"`
	MeasuredData             MeasuredDataSlice
}

func typeMapKey(i interface{}) reflect.Type {
	k := reflect.TypeOf(i)
	for k.Kind() == reflect.Ptr {
		k = k.Elem()
	}
	return k
}

// NewState returns a new instance of State.
func NewState() *State {
	return &State{
		SystemArtifacts: map[reflect.Type]SystemArtifact{},
		SubSystems:      map[reflect.Type]SubSystem{},
	}
}

// Reset returns to the initial state, but tries to keep the already allocated memory.
func (state *State) Reset() {
	for k := range state.SystemArtifacts {
		delete(state.SystemArtifacts, k)
	}
	for k := range state.SubSystems {
		delete(state.SubSystems, k)
	}
	state.CurrentActor = nil
	state.CurrentActionCoordinates = ActionCoordinates{}
	state.CurrentAction = nil
	state.MeasuredData = state.MeasuredData[:0]
}

// SetFlow sets the Flow and resets the execution carriage (resets to the first Step).
func (state *State) SetFlow(flow Flow) {
	coords := &state.CurrentActionCoordinates
	coords.Flow = flow
	coords.StepIndex = 0
	coords.ActionIndex = 0
}

// GetCurrentActionCoordinates returns the Action is being performed.
func (state *State) GetCurrentActionCoordinates() ActionCoordinates {
	return state.CurrentActionCoordinates
}

// GetSubSystemByTypeFromState extracts a specific SubSystem given its type.
//
// This was supposed to be a method of `*State`, but Go does not support generic
// methods, so it is a free function.
func GetSubSystemByTypeFromState[SS SubSystem](
	state *State,
) (SS, error) {
	var sample SS
	key := typeMapKey(sample)
	value, ok := state.SubSystems[key].(SS)
	if !ok {
		return value, ErrNoSubSystem{SubSystemKey: key}
	}
	return value, nil
}

// WithSubSystem extracts a specific SubSystem given its type.
//
// This was supposed to be a method of `*State`, but Go does not support generic
// methods, so it is a free function.
func WithSubSystem[SS SubSystem](
	state *State,
	callback func(subSystem SS) error,
) error {
	subSystem, err := GetSubSystemByTypeFromState[SS](state)
	if err != nil {
		return err
	}
	return callback(subSystem)
}

// IncludeSubSystem adds and enables a SubSystem, but each SubSystem type could
// be added only once.
func (state *State) IncludeSubSystem(subSystem SubSystem) {
	if reflect.TypeOf(subSystem).Kind() != reflect.Ptr {
		panic(fmt.Sprintf("%T is not a modifiable type", subSystem))
	}

	k := typeMapKey(subSystem)
	if _, ok := state.SubSystems[k]; ok {
		panic(fmt.Sprintf("double-setting of the same trust chain type: %s", k))
	}
	state.SubSystems[k] = subSystem
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
	callback func(systemArtifact SA) error,
) error {
	systemArtifact, err := GetSystemArtifactByTypeFromState[SA](state)
	if err != nil {
		return err
	}
	return callback(systemArtifact)
}

// IncludeSystemArtifact adds and enables a SystemArtifact, but each SystemArtifact type could
// be added only once.
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

// AddMeasuredData marks given data as protected/measured.
//
// TrustChain defines within which TrustChain this measurement was performed (should not be nil).
// DataSource defines how the data source was defined in the flow, which made the measurement (should not be nil).
func (state *State) AddMeasuredData(
	data Data,
	trustChain TrustChain,
	dataSource DataSource,
) *MeasuredData {
	state.MeasuredData = append(state.MeasuredData, MeasuredData{
		Data:       data,
		DataSource: dataSource,
		Actor:      state.CurrentActor,
		Action:     state.CurrentAction,
		TrustChain: trustChain,
	})
	return &state.MeasuredData[len(state.MeasuredData)-1]
}

// String implements fmt.Stringer.
func (state *State) String() string {
	var result strings.Builder
	if len(state.SystemArtifacts) > 0 {
		fmt.Fprintf(&result, "SystemArtifacts:\n\t%s\n", nestedStringOf(state.SystemArtifacts))
	}
	if len(state.SubSystems) > 0 {
		fmt.Fprintf(&result, "SubSystems:\n\t%s\n", nestedStringOf(state.SubSystems))
	}
	if len(state.CurrentActionCoordinates.Flow) > 0 {
		fmt.Fprintf(&result, "CurrentFlow:\n\t%s\n", nestedStringOf(state.CurrentActionCoordinates.Flow))
		fmt.Fprintf(&result, "CurrentStepIndex: %d\n", state.CurrentActionCoordinates.StepIndex)
	}
	if len(state.MeasuredData) > 0 {
		fmt.Fprintf(&result, "MeasuredData:\n\t%s\n", nestedStringOf(state.MeasuredData))
	}
	return result.String()
}

// GetDataMeasuredBy returns MeasuredData which was measured within the specified TrustChain.
//
// See also (*State).AddMeasuredData().
func (state *State) GetDataMeasuredBy(trustChain TrustChain) MeasuredDataSlice {
	var result MeasuredDataSlice
	for _, measuredData := range state.MeasuredData {
		if measuredData.TrustChain == trustChain {
			result = append(result, measuredData)
		}
	}
	return result
}
