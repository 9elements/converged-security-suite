package tpm

import (
	"context"

	"github.com/9elements/converged-security-suite/v2/pkg/bootflow/subsystems/trustchains/tpm/pcr"
	"github.com/9elements/converged-security-suite/v2/pkg/bootflow/types"
	"github.com/9elements/converged-security-suite/v2/pkg/tpmeventlog"
	"github.com/google/go-tpm/legacy/tpm2"
)

const (
	// currently we support only PCR0 and PCR1
	//
	// TODO: move this value into TPM settings
	PCRRegistersAmount = 2
)

var _ types.SubSystem = (*TPM)(nil)

// Algorithm is just a type-alias.
type Algorithm = pcr.Algorithm

// TPM is a TrustChain implementation which represents
// measured boot backed by a Trusted Platform Module (TPM).
type TPM struct {
	SupportedAlgos []Algorithm
	PCRValues      PCRValues
	CommandLog     CommandLog
	EventLog       EventLog
}

// NewTPM returns a new instance of TPM.
func NewTPM() *TPM {
	tpm := &TPM{}
	tpm.init()
	return tpm
}

// Reset cleans up the state of TPM as it never received any commands.
func (tpm *TPM) Reset() {
	tpm.DoNotUse_ResetNoInit()
	tpm.init()
}

// DoNotUse_ResetNoInit cleans up the state of TPM as it never received any commands,
// but does not set the state to a correct one.
//
// Do no use this function unless you know what are you doing.
//
// TODO: try to get rid of this function (or at least make it private).
func (tpm *TPM) DoNotUse_ResetNoInit() {
	tpm.SupportedAlgos = tpm.SupportedAlgos[:0]
	tpm.PCRValues = tpm.PCRValues[:0]
	tpm.CommandLog = tpm.CommandLog[:0]
	tpm.EventLog = tpm.EventLog[:0]

	// TODO: add an unit-test to check if everything is reset
}

func (tpm *TPM) init() {
	if cap(tpm.SupportedAlgos) < len(cachedSupportedHashAlgos) {
		tpm.SupportedAlgos = SupportedHashAlgos()
		return
	}

	tpm.SupportedAlgos = tpm.SupportedAlgos[:len(cachedSupportedHashAlgos)]
	copy(tpm.SupportedAlgos, cachedSupportedHashAlgos)
}

// CommandLogInfoProvider is an abstract provider of additional/optional information
// to be added to the CommandLog.
type CommandLogInfoProvider interface {
	CauseCoordinates() types.ActionCoordinates
	CauseAction() types.Action
}

// SupportedHashAlgos the list of currently supported hashing algorithms.
func SupportedHashAlgos() []Algorithm {
	return []Algorithm{
		tpm2.AlgSHA1,
		tpm2.AlgSHA256,
	}
}

var tpmMaxHashAlgo Algorithm
var cachedSupportedHashAlgos []Algorithm

func init() {
	supportedAlgos := SupportedHashAlgos()
	tpmMaxHashAlgo = supportedAlgos[0]
	for _, algo := range supportedAlgos {
		if algo > tpmMaxHashAlgo {
			tpmMaxHashAlgo = algo
		}
	}

	cachedSupportedHashAlgos = supportedAlgos
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
	var (
		causeCoords CauseCoordinates
		causeAction types.Action
	)
	if logInfo != nil {
		causeCoords = logInfo.CauseCoordinates()
		causeAction = logInfo.CauseAction()
	}
	tpm.CommandLog = append(
		tpm.CommandLog,
		newCommandLogEntry(
			cmd,
			causeCoords,
			causeAction,
		),
	)
	return cmd.Apply(ctx, tpm)
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
	hashAlgo Algorithm,
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
	hashAlgo Algorithm,
	digest Digest,
	evType tpmeventlog.EventType,
	data []byte,
	info CommandLogInfoProvider,
) error {
	return tpm.TPMExecute(ctx, NewCommandEventLogAdd(
		*NewCommandExtend(
			pcrIndex,
			hashAlgo,
			digest,
		),
		evType,
		data,
	), info)
}
