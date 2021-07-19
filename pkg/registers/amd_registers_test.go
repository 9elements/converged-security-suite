package registers

import (
	"reflect"
	"testing"
)

func TestMP0C2PMsg37Register(t *testing.T) {
	var rawValue uint32 = 0x110000AD
	reg := ParseMP0C2PMsg37Register(rawValue)

	if reg.ID() != MP0C2PMSG37RegisterID {
		t.Errorf("Unexpected id '%s' of the register", reg.ID())
	}
	if reg.Raw() != rawValue {
		t.Errorf("Unexecpted raw value '%d' of the register", reg.Raw())
	}
	if reg.BitSize() != 32 {
		t.Errorf("Unexecpted bit size '%d' of the register", reg.BitSize())
	}

	if !reg.IsPlatformSecureBootEnabled() {
		t.Errorf("Unexepcted value of platform secure boot enabled '%t' of the register", reg.IsPlatformSecureBootEnabled())
	}

	fields := reg.Fields()
	if len(fields) != 3 {
		t.Errorf("Unexepcted value of fields '%d' of the register", len(fields))
	}

	platformSecureBootFieldFieldValue := FieldValueToNumber(fields[1].Value)
	if platformSecureBootFieldFieldValue != 1 {
		t.Errorf("Unexepcted value of platform secure boot enabled '%d' of the register", platformSecureBootFieldFieldValue)
	}
}

func TestRegistersCollection(t *testing.T) {
	regs := Registers{
		ParseMP0C2PMsg37Register(1234),
		ParseMP0C2PMsg38Register(5678),
	}

	testCases := []struct {
		registerIndex int
		findFunction  func(regs Registers) (interface{}, bool)
	}{
		{
			registerIndex: 0,
			findFunction: func(regs Registers) (interface{}, bool) {
				return FindMP0C2PMsg37(regs)
			},
		},
		{
			registerIndex: 1,
			findFunction: func(regs Registers) (interface{}, bool) {
				return FindMP0C2PMsg38(regs)
			},
		},
	}

	for _, testCase := range testCases {
		r, found := testCase.findFunction(regs)
		if !found {
			t.Errorf("%s register is not found", regs[testCase.registerIndex].ID())
			continue
		}
		if !reflect.DeepEqual(r, regs[testCase.registerIndex]) {
			t.Errorf("found register: '%v' doesn't match the one in collection: '%v", r, regs[testCase.registerIndex])
		}
	}
}
