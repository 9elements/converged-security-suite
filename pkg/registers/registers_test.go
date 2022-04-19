package registers_test

import (
	"encoding/json"
	"reflect"
	"testing"

	"github.com/9elements/converged-security-suite/v2/pkg/registers"
	"gopkg.in/yaml.v3"
)

func registersSample() registers.Registers {
	regs := registers.Registers{
		registers.ParseACMPolicyStatusRegister(0x42),
		registers.ParseIA32SMRRPhysBase(42),
		registers.ParseTXTPublicKey([32]byte{1, 2, 3}),
	}
	regs.Sort()
	return regs
}

func TestOBSOLETEJSONMarshaling(t *testing.T) {
	initialRegisters := registersSample()

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

func TestYAMLMarshaling(t *testing.T) {
	initialRegisters := registersSample()

	b, err := yaml.Marshal(initialRegisters)
	if err != nil {
		t.Errorf("failed to marshal registers to YAML, err: %v", err)
		t.Skip()
	}

	var resultRegisters registers.Registers
	if err := yaml.Unmarshal(b, &resultRegisters); err != nil {
		t.Errorf("failed to unmarshal registers from YAML, err: %v", err)
		t.Skip()
	}

	if !reflect.DeepEqual(initialRegisters, resultRegisters) {
		t.Errorf("result registers %v are not equal to the initial %v", initialRegisters, resultRegisters)
	}
}
