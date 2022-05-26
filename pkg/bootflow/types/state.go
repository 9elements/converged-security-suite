package types

// State describes a virtual state of a machine being booted
type State struct {
	SystemArtifacts SystemArtifacts
	TrustChains     TrustChains
	CurrentFlow     Flow
	CurrentStepIdx  uint
	VerifiedData    []VerifiedData
}

func (state *State) AddVerifiedData(trustChain TrustChain, data Data) {
	if data.ForceBytes != nil {
		return
	}

	state.VerifiedData = append(state.VerifiedData, VerifiedData{
		Data:       data,
		TrustChain: trustChain,
	})
}
