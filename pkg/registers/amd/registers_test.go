package amd

import (
	"testing"

	"github.com/9elements/converged-security-suite/v2/pkg/registers"
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

	platformSecureBootFieldFieldValue := registers.FieldValueToNumber(fields[1].Value)
	if platformSecureBootFieldFieldValue != 1 {
		t.Errorf("Unexepcted value of platform secure boot enabled '%d' of the register", platformSecureBootFieldFieldValue)
	}
}
