package registers_test

import (
	"encoding/json"
	"github.com/9elements/converged-security-suite/v2/pkg/registers"
	"reflect"
	"testing"
)

func TestJSONMarshaling(t *testing.T) {
	initialRegisters := registers.Registers{
		registers.ParseACMPolicyStatusRegister(0x42),
		registers.ParseIA32SMRRPhysBase(42),
	}

	b, err := json.Marshal(initialRegisters)
	if err != nil {
		t.Errorf("failed to marshal registers to JSON, err: %v", err)
		t.Skip()
	}

	var resultRegisters registers.Registers
	if err := json.Unmarshal(b, &resultRegisters); err != nil {
		t.Errorf("failed to unmarshal registers from JSON, err: %v", err)
		t.Skip()
	}

	if !reflect.DeepEqual(initialRegisters, resultRegisters) {
		t.Errorf("result registers %v are not equal to the initial %v", initialRegisters, resultRegisters)
	}
}
