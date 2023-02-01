package datasources

import (
	"fmt"

	"github.com/9elements/converged-security-suite/v2/pkg/bootflow/conditions/ocpconds"
	"github.com/9elements/converged-security-suite/v2/pkg/bootflow/types"
)

type PCDVariable string

var _ types.DataSource = PCDVariable("")

// Data implements types.DataSource.
func (d PCDVariable) Data(s *types.State) (*types.Data, error) {
	switch string(d) {
	case "FirmwareVendorVersion":
		switch {
		case ocpconds.IsOCPv0{}.Check(s):
			return &types.Data{
				ForceBytes: (ocpconds.IsOCPv0{}).FirmwareVendorVersion(),
			}, nil
		case ocpconds.IsOCPv1{}.Check(s):
			return &types.Data{
				ForceBytes: (ocpconds.IsOCPv1{}).FirmwareVendorVersion(),
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
