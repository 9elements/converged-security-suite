package biosconds

import (
	"context"
	"regexp"

	"github.com/9elements/converged-security-suite/v2/pkg/bootflow/systemartifacts/biosimage"
	"github.com/9elements/converged-security-suite/v2/pkg/bootflow/types"
	"github.com/facebookincubator/go-belt/tool/logger"
)

// VersionRegexp is a types.Condition which returns true if BIOS firmware
// version matches the defined regular expression.
type VersionRegexp string

var _ types.Condition = VersionRegexp("")

func (verRegexp VersionRegexp) Check(
	ctx context.Context,
	state *types.State,
) bool {
	biosImg, err := biosimage.Get(state)
	if err != nil {
		logger.FromCtx(ctx).Debugf("unable to obtain BIOS firmware image: %v", err)
		return false
	}

	r, err := regexp.Compile(string(verRegexp))
	if err != nil {
		logger.FromCtx(ctx).Error("unable to compile regular expression '%s': %v", string(verRegexp), err)
		return false
	}

	biosInfo, err := biosImg.Info()
	if err != nil {
		logger.FromCtx(ctx).Error("unable to obtain BIOS info: %v", string(verRegexp), err)
		return false
	}

	return r.MatchString(biosInfo.Version)
}
