package datasources

import (
	"encoding/hex"
	"fmt"

	"github.com/9elements/converged-security-suite/v2/pkg/bootflow/conditions/ocpconds"
	"github.com/9elements/converged-security-suite/v2/pkg/bootflow/types"
)

type PCDVariable string

var _ types.DataSource = PCDVariable("")

var (
	ocpVendorVersion = unhex("1EFB6B540C1D5540A4AD4EF4BF17B83A")
)

func unhex(in string) []byte {
	out, err := hex.DecodeString(in)
	if err != nil {
		panic(err)
	}
	return out
}

// Data implements types.DataSource.
func (d PCDVariable) Data(s *types.State) (*types.Data, error) {
	switch string(d) {
	case "FirmwareVendorVersion":
		switch {
		case ocpconds.IsOCP{}.Check(s):
			return &types.Data{
				ForceBytes: ocpVendorVersion,
			}, nil
		default:
			return nil, fmt.Errorf("no PCD parser is defined for this case")
		}
	default:
		return nil, fmt.Errorf("unknown PCD variable '%s'", string(d))
	}
}

// String implements fmt.Stringer.
func (d PCDVariable) String() string {
	return fmt.Sprintf(`PCDVariable("%s")`, string(d))
}
