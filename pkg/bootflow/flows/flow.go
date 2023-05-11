package flows

import (
	"fmt"
	"sort"
	"strings"

	"github.com/9elements/converged-security-suite/v2/pkg/bootflow/types"
)

var registry = map[string]types.Flow{}

// NewFlow adds a flow into the registry
func NewFlow(name string, steps types.Steps) types.Flow {
	flow := types.Flow{
		Name:  name,
		Steps: steps,
	}
	k := strings.ToLower(flow.Name)
	if _, ok := registry[k]; ok {
		panic(fmt.Sprintf("flow '%s' is already registered", k))
	}
	registry[strings.ToLower(flow.Name)] = flow
	return flow
}

// GetFlowByName returns a Flow given its name.
//
// The second value is false if there is no such flow.
func GetFlowByName(name string) (types.Flow, bool) {
	flow, ok := registry[strings.ToLower(name)]
	return flow, ok
}

// All return all known flows.
func All() []types.Flow {
	result := make([]types.Flow, 0, len(registry))
	for _, flow := range registry {
		result = append(result, flow)
	}
	sort.Slice(result, func(i, j int) bool {
		return result[i].Name < result[j].Name
	})
	return result
}
