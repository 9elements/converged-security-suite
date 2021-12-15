package pcr

import (
	"testing"

	"github.com/klauspost/cpuid/v2"
	"github.com/stretchr/testify/require"
)

func TestFlowCPUVendorID(t *testing.T) {
	for _, flow := range Flows {
		if flow == FlowAuto {
			continue
		}
		require.NotEqual(t, cpuid.VendorUnknown, flow.CPUVendorID(), flow.String())
	}
}
