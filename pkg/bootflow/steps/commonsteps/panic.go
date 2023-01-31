package commonsteps

import (
	"fmt"
	"strings"

	"github.com/9elements/converged-security-suite/v2/pkg/bootflow/actions/commonactions"
	"github.com/9elements/converged-security-suite/v2/pkg/bootflow/types"
)

type Panic string

func (p Panic) Actions(s *types.State) types.Actions {
	return types.Actions{
		commonactions.Panic(fmt.Errorf("%s", string(p))),
	}
}

func (p Panic) String() string {
	return fmt.Sprintf(`Panic("%s")`, strings.ReplaceAll(string(p), `"`, `\"`))
}
