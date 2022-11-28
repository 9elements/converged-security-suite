package tpm

import (
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

type LogInfoProvider interface {
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

func (tpm *TPM) TPMExecute(cmd Command, logInfo LogInfoProvider) error {
	tpm.CommandLog = append(
		tpm.CommandLog,
		newCommandLogEntry(
			cmd,
			logInfo.CauseCoordinates(),
		),
	)
	return cmd.apply(tpm)
}

func (tpm *TPM) TPMInit(locality uint8, info LogInfoProvider) error {
	return tpm.TPMExecute(NewCommandInit(
		locality,
	), info)
}

func (tpm *TPM) TPMExtend(
	pcrIndex PCRID,
	hashAlgo tpm2.Algorithm,
	digest []byte,
	info LogInfoProvider,
) error {
	return tpm.TPMExecute(NewCommandExtend(
		pcrIndex,
		hashAlgo,
		digest,
	), info)
}

func (tpm *TPM) TPMEventLogAdd(
	pcrIndex PCRID,
	hashAlgo tpm2.Algorithm,
	digest Digest,
	data []byte,
	info LogInfoProvider,
) error {
	return tpm.TPMExecute(NewCommandEventLogAdd(
		NewCommandExtend(
			pcrIndex,
			hashAlgo,
			digest,
		),
		data,
	), info)
}
