package commonactions

import (
	"context"
	"fmt"

	"github.com/9elements/converged-security-suite/v2/pkg/bootflow/types"
)

type panicT struct {
	Error error
}

var _ types.Action = (*panicT)(nil)

func Panic(e error) panicT {
	return panicT{Error: e}
}

func (p panicT) Apply(_ context.Context, _ *types.State) error {
	panic(p.Error)
}

func (p panicT) String() string {
	return fmt.Sprintf(`Panic(<%v>)`, p.Error)
}
