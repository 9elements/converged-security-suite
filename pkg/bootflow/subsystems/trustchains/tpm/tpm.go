package tpm

import (
	"context"

	"github.com/9elements/converged-security-suite/v2/pkg/bootflow/types"
	"github.com/google/go-tpm/tpm2"
)

const (
	// currently we support only PCR0 and PCR1
	PCRRegistersAmount = 2
)

var _ types.SubSystem = (*TPM)(nil)

// TPM is a TrustChain implementation which represents
// measured boot backed by a Trusted Platform Module (TPM).
type TPM struct {
	PCRValues  PCRValues
	CommandLog CommandLog
	EventLog   EventLog
}

// NewTPM returns a new instance of TPM.
func NewTPM() *TPM {
	return &TPM{}
}

// Reset cleans up the state of TPM as it never received any commands.
func (tpm *TPM) Reset() {
	*tpm = *NewTPM()
}

// CommandLogInfoProvider is an abstract provider of additional/optional information
// to be added to the CommandLog.
type CommandLogInfoProvider interface {
	CauseCoordinates() types.ActionCoordinates
}

// SupportedHashAlgos the list of currently supported hashing algorithms.
func SupportedHashAlgos() []tpm2.Algorithm {
	return []tpm2.Algorithm{
		tpm2.AlgSHA1,
		tpm2.AlgSHA256,
	}
}

var tpmMaxHashAlgo tpm2.Algorithm

func init() {
	supportedAlgos := SupportedHashAlgos()
	tpmMaxHashAlgo = supportedAlgos[0]
	for _, algo := range supportedAlgos {
		if algo > tpmMaxHashAlgo {
			tpmMaxHashAlgo = algo
		}
	}
}

// GetFrom returns a TPM given a State.
func GetFrom(state *types.State) (*TPM, error) {
	return types.GetSubSystemByTypeFromState[*TPM](state)
}

// IsInitialized returns if CommandInit was ever executed.
func (tpm *TPM) IsInitialized() bool {
	if tpm == nil {
		return false
	}
	return len(tpm.PCRValues) > 0
}

// TPMExecute executes an abstract command.
func (tpm *TPM) TPMExecute(ctx context.Context, cmd Command, logInfo CommandLogInfoProvider) error {
	var causeCoords CauseCoordinates
	if logInfo != nil {
		causeCoords = logInfo.CauseCoordinates()
	}
	tpm.CommandLog = append(
		tpm.CommandLog,
		newCommandLogEntry(
			cmd,
			causeCoords,
		),
	)
	return cmd.apply(ctx, tpm)
}

// TPMInit is just a wrapper which creates a CommandInit and executes it.
func (tpm *TPM) TPMInit(ctx context.Context, locality uint8, info CommandLogInfoProvider) error {
	return tpm.TPMExecute(ctx, NewCommandInit(
		locality,
	), info)
}

// TPMExtend is just a wrapper which creates CommandExtend and executes it.
func (tpm *TPM) TPMExtend(
	ctx context.Context,
	pcrIndex PCRID,
	hashAlgo tpm2.Algorithm,
	digest []byte,
	info CommandLogInfoProvider,
) error {
	return tpm.TPMExecute(ctx, NewCommandExtend(
		pcrIndex,
		hashAlgo,
		digest,
	), info)
}

// TPMEventLogAdd is just a wrapper which creates CommandEventLogAdd and executes it.
func (tpm *TPM) TPMEventLogAdd(
	ctx context.Context,
	pcrIndex PCRID,
	hashAlgo tpm2.Algorithm,
	digest Digest,
	data []byte,
	info CommandLogInfoProvider,
) error {
	return tpm.TPMExecute(ctx, NewCommandEventLogAdd(
		*NewCommandExtend(
			pcrIndex,
			hashAlgo,
			digest,
		),
		data,
	), info)
}
