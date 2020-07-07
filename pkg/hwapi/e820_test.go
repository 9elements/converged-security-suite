package hwapi

import (
	"testing"
)

func TestE820ReservedCheck(t *testing.T) {
	t.Skip()
	ranges := []struct {
		start uint64
		end   uint64
	}{
		{0, 0x10},
		{0x8c000, 0x8ffff},
		{0x7bef5000, 0x7bef5010},
	}
	txtAPI := GetAPI()

	for _, s := range ranges {
		reserved, err := txtAPI.IsReservedInE820(s.start, s.end)
		if err != nil {
			t.Errorf("Checking range %x-%x failed: %s", s.start, s.end, err)
		}

		t.Logf("range %x-%x: %t", s.start, s.end, reserved)
	}
}
