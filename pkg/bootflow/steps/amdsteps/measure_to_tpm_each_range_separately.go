package amdsteps

import (
	"context"
	"fmt"

	"github.com/9elements/converged-security-suite/v2/pkg/bootflow/actions/commonactions"
	"github.com/9elements/converged-security-suite/v2/pkg/bootflow/actions/tpmactions"
	"github.com/9elements/converged-security-suite/v2/pkg/bootflow/datasources"
	"github.com/9elements/converged-security-suite/v2/pkg/bootflow/types"
	pcrtypes "github.com/9elements/converged-security-suite/v2/pkg/pcr/types"
	"github.com/9elements/converged-security-suite/v2/pkg/tpmeventlog"
	pkgbytes "github.com/linuxboot/fiano/pkg/bytes"
)

func measureToTPMEachRangeSeparately(
	ctx context.Context,
	s *types.State,
	pcrID pcrtypes.ID,
	dataSource types.DataSource,
	eventType tpmeventlog.EventType,
	comment string,
) types.Actions {
	data, err := dataSource.Data(ctx, s)
	if err != nil {
		return types.Actions{
			commonactions.Panic(fmt.Errorf("unable to get data from source %#+v: %w", dataSource, err)),
		}
	}

	var actions types.Actions
	for refIdx, ref := range data.References {
		for rangeIdx, r := range ref.Ranges {
			actions = append(actions, tpmactions.NewTPMEvent(
				pcrtypes.ID(0),
				(*datasources.StaticData)(types.NewData(&types.Reference{
					Artifact: ref.Artifact,
					MappedRanges: types.MappedRanges{
						AddressMapper: ref.AddressMapper,
						Ranges:        []pkgbytes.Range{r},
					},
				})),
				eventType,
				[]byte(fmt.Sprintf("%s_%d_%d", comment, refIdx, rangeIdx)),
			))
		}
	}

	return actions
}
