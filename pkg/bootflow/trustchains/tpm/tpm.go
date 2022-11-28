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

func (tpm *TPM) TPMExecute(cmd Command, causeAction types.Action) error {
	tpm.CommandLog = append(tpm.CommandLog, newCommandLogEntry(cmd, causeAction))
	return cmd.apply(tpm)
}

func (tpm *TPM) TPMInit(locality uint8, causeAction types.Action) error {
	return tpm.TPMExecute(NewCommandInit(
		locality,
	), causeAction)
}

func (tpm *TPM) TPMExtend(
	pcrIndex PCRID,
	hashAlgo tpm2.Algorithm,
	digest []byte,
	causeAction types.Action,
) error {
	return tpm.TPMExecute(NewCommandExtend(
		pcrIndex,
		hashAlgo,
		digest,
	), causeAction)
}

func (tpm *TPM) TPMEventLogAdd(
	pcrIndex PCRID,
	hashAlgo tpm2.Algorithm,
	digest Digest,
	data []byte,
	causeAction types.Action,
) error {
	return tpm.TPMExecute(NewCommandEventLogAdd(
		NewCommandExtend(
			pcrIndex,
			hashAlgo,
			digest,
		),
		data,
	), causeAction)
}
