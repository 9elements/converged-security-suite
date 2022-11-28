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

var _ types.TrustChain = (*TPM)(nil)

type TPM struct {
	PCRValues  PCRValues
	CommandLog CommandLog
	EventLog   EventLog
}

func NewTPM() *TPM {
	return &TPM{}
}

func (tpm *TPM) Reset() {
	*tpm = *NewTPM()
}

type CommandLogInfoProvider interface {
	CauseCoordinates() types.ActionCoordinates
}

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

func GetFrom(state *types.State) (*TPM, error) {
	return types.GetTrustChainByTypeFromState[*TPM](state)
}

func (tpm *TPM) IsInitialized() bool {
	return len(tpm.PCRValues) > 0
}

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

func (tpm *TPM) TPMInit(ctx context.Context, locality uint8, info CommandLogInfoProvider) error {
	return tpm.TPMExecute(ctx, NewCommandInit(
		locality,
	), info)
}

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
