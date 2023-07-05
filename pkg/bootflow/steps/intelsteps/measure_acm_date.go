package intelsteps

import (
	"context"

	"github.com/9elements/converged-security-suite/v2/pkg/bootflow/actions/tpmactions"
	"github.com/9elements/converged-security-suite/v2/pkg/bootflow/datasources/inteldata"
	"github.com/9elements/converged-security-suite/v2/pkg/bootflow/subsystems/trustchains/tpm/pcr"
	"github.com/9elements/converged-security-suite/v2/pkg/bootflow/types"
	"github.com/9elements/converged-security-suite/v2/pkg/tpmeventlog"
)

// MeasureACMDate measures ACM date to TPM.
//
// Note: this action does not support TPM1.2 behavior,
// because in TPM1.2 the ACM date is not hashed.
type MeasureACMDate struct{}

var _ types.Step = (*MeasureACMDate)(nil)

// Actions implements types.Step.
func (MeasureACMDate) Actions(ctx context.Context, state *types.State) types.Actions {
	return types.Actions{
		tpmactions.NewTPMEvent(
			pcr.ID(0),
			inteldata.ACMDate{},
			tpmeventlog.EV_S_CRTM_CONTENTS,
			[]byte("ACM_date"),
		),
	}
}
