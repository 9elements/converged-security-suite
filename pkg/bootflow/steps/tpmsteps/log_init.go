package tpmsteps

import (
	"context"
	"fmt"

	"github.com/9elements/converged-security-suite/v2/pkg/bootflow/actions/commonactions"
	"github.com/9elements/converged-security-suite/v2/pkg/bootflow/actions/tpmactions"
	"github.com/9elements/converged-security-suite/v2/pkg/bootflow/subsystems/trustchains/tpm"
	"github.com/9elements/converged-security-suite/v2/pkg/bootflow/types"
	"github.com/9elements/converged-security-suite/v2/pkg/tpmeventlog"
)

type LogInitStruct struct {
	Locality uint8
}

func LogInit(locality uint8) types.Step {
	return LogInitStruct{Locality: locality}
}

func (s LogInitStruct) Actions(ctx context.Context, state *types.State) types.Actions {
	tpmInstance, err := tpm.GetFrom(state)
	if err != nil {
		return types.Actions{
			commonactions.Panic(fmt.Errorf("unable to access TPM: %w", err)),
		}
	}

	var result types.Actions
	for _, algo := range tpmInstance.SupportedAlgos {
		h, err := algo.Hash()
		if err != nil {
			return types.Actions{
				commonactions.Panic(fmt.Errorf("unable to initialize hashes for algo %s: %w", algo, err)),
			}
		}
		result = append(result, tpmactions.NewTPMEventLogAdd(
			0,
			algo,
			make([]byte, h.Size()),
			tpmeventlog.EV_NO_ACTION,
			[]byte(fmt.Sprintf("StartupLocality\x00%d", s.Locality)),
		))
	}
	return result
}
