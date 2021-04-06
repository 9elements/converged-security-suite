package registers_test

import (
	"fmt"
	"testing"

	"github.com/9elements/converged-security-suite/v2/pkg/registers"
)

type MSRReaderMock struct {
	values map[int64]uint64
}

func (m *MSRReaderMock) Read(msr int64) (uint64, error) {
	v, found := m.values[msr]
	if !found {
		return 0, fmt.Errorf("MSRReaderMock: value by address %d is not found", msr)
	}
	return v, nil
}

func (m *MSRReaderMock) add(addr int64, value uint64) *MSRReaderMock {
	m.values[addr] = value
	return m
}

func newMSRReaderMock() *MSRReaderMock {
	return &MSRReaderMock{
		values: make(map[int64]uint64),
	}
}

func fieldValueToBoolean(v []byte) bool {
	return registers.FieldValueToNumber(v) != 0
}

func simpleMSRReaderMock(addr int64, val uint64) *MSRReaderMock {
	m := newMSRReaderMock()
	m.add(addr, val)
	return m
}

func doesRegisterSupportRawAccessor(r registers.Register) bool {
	switch r.(type) {
	case registers.RawRegister, registers.RawRegister8, registers.RawRegister16, registers.RawRegister32, registers.RawRegister64:
		return true
	}
	return false
}

func TestReadMSRRegisters(t *testing.T) {
	msrRegistersOffsets := []int64{
		registers.BootGuardPBECRegisterOffset,
		registers.BTGSACMInfoRegisterOffset,
		registers.IA32DebugInterfaceRegisterOffset,
		registers.IA32FeatureControlRegisterOffset,
		registers.IA32MTRRCAPRegisterOffset,
		registers.IA32PlatformIDRegisterOffset,
		registers.IA32SMRRPhysBaseRegisterOffset,
		registers.IA32SMRRPhysMaskRegisterOffset,
	}

	mock := newMSRReaderMock()
	for _, offset := range msrRegistersOffsets {
		mock.add(offset, 0)
	}

	regs, err := registers.ReadMSRRegisters(mock)
	if err != nil {
		t.Skipf("ReadMSRRegisters returned an error: %v", err)
	}

	if len(regs) != len(msrRegistersOffsets) {
		t.Errorf("Expected registers count %d, but got %d", len(msrRegistersOffsets), len(regs))
	}

	t.Run("no_duplicates", func(t *testing.T) {
		allIDs := make(map[registers.RegisterID]struct{})
		for _, reg := range regs {
			if reg == nil {
				t.Errorf("A nil register is found")
				t.Skip()
			}

			if !doesRegisterSupportRawAccessor(reg) {
				t.Errorf("Register %s doesn't support any of the raw access interfaces", reg.ID())
			}

			foundReg := regs.Find(reg.ID())
			if foundReg == nil {
				t.Errorf("Unable to find the register with ID %s in collection", reg.ID())
			}

			_, found := allIDs[reg.ID()]
			if found {
				t.Errorf("Register with id %s has multiple occurences", reg.ID())
			}
			allIDs[reg.ID()] = struct{}{}
		}
	})

	t.Run("support_raw_interface", func(t *testing.T) {
		for _, reg := range regs {
			if !doesRegisterSupportRawAccessor(reg) {
				t.Errorf("Register %s doesn't support any of the raw access interfaces", reg.ID())
			}
		}
	})

	t.Run("all_registers_are_found", func(t *testing.T) {
		// Use wrapper to bypass "multiple-value XXX in single-value context" compilation error
		type findResult struct {
			reg   registers.Register
			found bool
		}
		wrapResult := func(reg registers.Register, found bool) findResult {
			return findResult{
				reg:   reg,
				found: found,
			}
		}
		checkIsFound := func(res findResult, registerName string) {
			if !res.found {
				t.Errorf("%s register is not found", registerName)
			}
			if res.reg == nil {
				t.Errorf("%s register result value is nil", registerName)
			}
		}

		checkIsFound(wrapResult(registers.FindBootGuardPBEC(regs)), "BootGuardPBEC")
		checkIsFound(wrapResult(registers.FindBTGSACMInfo(regs)), "BTGSACMInfo")
		checkIsFound(wrapResult(registers.FindIA32DebugInterface(regs)), "IA32DebugInterface(")
		checkIsFound(wrapResult(registers.FindIA32FeatureControl(regs)), "IA32FeatureControl")
		checkIsFound(wrapResult(registers.FindIA32MTRRCAP(regs)), "IA32MTRRCAP")
		checkIsFound(wrapResult(registers.FindIA32PlatformID(regs)), "IA32PlatformID")
		checkIsFound(wrapResult(registers.FindIA32SMRRPhysBase(regs)), "IA32SMRRPhysBase")
		checkIsFound(wrapResult(registers.FindIA32SMRRPhysMask(regs)), "IA32SMRRPhysMask")
	})
}

func TestIA32FeatureControlRegister(t *testing.T) {
	reg := registers.ParseIA32FeatureControl(0)
	if reg.ID() != registers.IA32FeatureControlRegisterID {
		t.Errorf("register ID %s is incorrect", reg.ID())
	}
	if reg.BitSize() != 64 {
		t.Errorf("Bit size %d is incorrect", reg.BitSize())
	}

	type parsedIA32FeatureControl struct {
		Locked                 bool
		VMXOnForSMXEnabled     bool
		VMXOnOutsideSMXEnabled bool
		SENTEREnables          uint8
		SENTERGlobalEnable     bool
	}

	convert := func(reg registers.IA32FeatureControl) parsedIA32FeatureControl {
		return parsedIA32FeatureControl{
			Locked:                 reg.Locked(),
			VMXOnForSMXEnabled:     reg.VMXInSMXEnabled(),
			VMXOnOutsideSMXEnabled: reg.VMXOutsideSMXEnabled(),
			SENTEREnables:          reg.SENTEREnables(),
			SENTERGlobalEnable:     reg.SENTERGlobalEnable(),
		}
	}

	constructFromFields := func(field []registers.Field) parsedIA32FeatureControl {
		return parsedIA32FeatureControl{
			Locked:                 fieldValueToBoolean(field[0].Value),
			VMXOnForSMXEnabled:     fieldValueToBoolean(field[1].Value),
			VMXOnOutsideSMXEnabled: fieldValueToBoolean(field[2].Value),
			SENTEREnables:          uint8(registers.FieldValueToNumber(field[4].Value)),
			SENTERGlobalEnable:     fieldValueToBoolean(field[5].Value),
		}
	}

	testCases := []struct {
		rawValue uint64
		expected parsedIA32FeatureControl
	}{
		{
			rawValue: 0x10FF07,
			expected: parsedIA32FeatureControl{
				Locked:                 true,
				VMXOnForSMXEnabled:     true,
				VMXOnOutsideSMXEnabled: true,
				SENTEREnables:          0x7F,
				SENTERGlobalEnable:     true,
			},
		},
		{
			rawValue: 0x207F00,
			expected: parsedIA32FeatureControl{
				Locked:                 false,
				VMXOnForSMXEnabled:     false,
				VMXOnOutsideSMXEnabled: false,
				SENTEREnables:          0x7F,
				SENTERGlobalEnable:     false,
			},
		},
	}

	for _, testCase := range testCases {
		mock := simpleMSRReaderMock(registers.IA32FeatureControlRegisterOffset, testCase.rawValue)
		reg, err := registers.ReadIA32FeatureControl(mock)
		if err != nil {
			t.Errorf("Unexpected error %v during ReadIA32FeatureControl", err)
			t.Skip()
		}

		if reg.Raw() != testCase.rawValue {
			t.Errorf("Raw() value if the register is not equal to expected [%v != %v]", reg.Raw(), testCase.rawValue)
		}

		actual := convert(reg)
		if actual != testCase.expected {
			t.Errorf("Actual parsed register value is not equal to expected [%v != %v] ", actual, testCase.expected)
		}

		fields := reg.Fields()
		if len(fields) != 7 {
			t.Errorf("Unexpected number of fields: %d ", len(fields))
			continue
		}

		actual = constructFromFields(fields)
		if actual != testCase.expected {
			t.Errorf("Actual parsed register from fields value is not equal to expected [%v != %v] ", actual, testCase.expected)
		}
	}
}

func TestIA32SMRRPhysBaseRegister(t *testing.T) {
	reg := registers.ParseIA32SMRRPhysBase(0)
	if reg.ID() != registers.IA32SMRRPhysBaseRegisterID {
		t.Errorf("register ID %s is incorrect", reg.ID())
	}
	if reg.BitSize() != 64 {
		t.Errorf("Bit size %d is incorrect", reg.BitSize())
	}

	type parsedIA32SMRRPhysBase struct {
		Type     uint8
		PhysBase uint32
	}

	convert := func(reg registers.IA32SMRRPhysBase) parsedIA32SMRRPhysBase {
		return parsedIA32SMRRPhysBase{
			Type:     reg.Type(),
			PhysBase: reg.PhysBase(),
		}
	}

	constructFromFields := func(field []registers.Field) parsedIA32SMRRPhysBase {
		return parsedIA32SMRRPhysBase{
			Type:     uint8(registers.FieldValueToNumber(field[0].Value)),
			PhysBase: uint32(registers.FieldValueToNumber(field[2].Value)),
		}
	}

	testCases := []struct {
		rawValue uint64
		expected parsedIA32SMRRPhysBase
	}{
		{
			rawValue: 0x70000006,
			expected: parsedIA32SMRRPhysBase{
				Type:     0x6,
				PhysBase: 0x70000,
			},
		},
		{
			rawValue: 0xB20008AA,
			expected: parsedIA32SMRRPhysBase{
				Type:     0xAA,
				PhysBase: 0xB2000,
			},
		},
	}

	for _, testCase := range testCases {
		mock := simpleMSRReaderMock(registers.IA32SMRRPhysBaseRegisterOffset, testCase.rawValue)
		reg, err := registers.ReadIA32SMRRPhysBase(mock)
		if err != nil {
			t.Errorf("Unexpected error %v during ReadIA32FeatureControl", err)
			t.Skip()
		}

		if reg.Raw() != testCase.rawValue {
			t.Errorf("Raw() value if the register is not equal to expected [%v != %v]", reg.Raw(), testCase.rawValue)
		}

		actual := convert(reg)
		if actual != testCase.expected {
			t.Errorf("Actual parsed register value is not equal to expected [%v != %v] ", actual, testCase.expected)
		}

		fields := reg.Fields()
		if len(fields) != 4 {
			t.Errorf("Unexpected number of fields: %d ", len(fields))
			continue
		}

		actual = constructFromFields(fields)
		if actual != testCase.expected {
			t.Errorf("Actual parsed register from fields value is not equal to expected [%v != %v] ", actual, testCase.expected)
		}
	}
}

func TestIA32SMRRPhysMaskRegister(t *testing.T) {
	reg := registers.ParseIA32SMRRPhysMask(0)
	if reg.ID() != registers.IA32SMRRPhysMaskRegisterID {
		t.Errorf("register ID %s is incorrect", reg.ID())
	}
	if reg.BitSize() != 64 {
		t.Errorf("Bit size %d is incorrect", reg.BitSize())
	}

	type parsedIA32SMRRPhysMask struct {
		Valid    bool
		PhysMask uint32
	}

	convert := func(reg registers.IA32SMRRPhysMask) parsedIA32SMRRPhysMask {
		return parsedIA32SMRRPhysMask{
			Valid:    reg.Valid(),
			PhysMask: reg.PhysMask(),
		}
	}

	constructFromFields := func(field []registers.Field) parsedIA32SMRRPhysMask {
		return parsedIA32SMRRPhysMask{
			Valid:    fieldValueToBoolean(field[1].Value),
			PhysMask: uint32(registers.FieldValueToNumber(field[2].Value)),
		}
	}

	testCases := []struct {
		rawValue uint64
		expected parsedIA32SMRRPhysMask
	}{
		{
			rawValue: 0xF8000800,
			expected: parsedIA32SMRRPhysMask{
				Valid:    true,
				PhysMask: 0xF8000,
			},
		},
		{
			rawValue: 0xAA000000,
			expected: parsedIA32SMRRPhysMask{
				Valid:    false,
				PhysMask: 0xAA000,
			},
		},
	}

	for _, testCase := range testCases {
		mock := simpleMSRReaderMock(registers.IA32SMRRPhysMaskRegisterOffset, testCase.rawValue)
		reg, err := registers.ReadIA32SMRRPhysMask(mock)
		if err != nil {
			t.Errorf("Unexpected error %v during ReadIA32FeatureControl", err)
			t.Skip()
		}

		if reg.Raw() != testCase.rawValue {
			t.Errorf("Raw() value if the register is not equal to expected [%v != %v]", reg.Raw(), testCase.rawValue)
		}

		actual := convert(reg)
		if actual != testCase.expected {
			t.Errorf("Actual parsed register value is not equal to expected [%v != %v] ", actual, testCase.expected)
		}

		fields := reg.Fields()
		if len(fields) != 4 {
			t.Errorf("Unexpected number of fields: %d ", len(fields))
			continue
		}

		actual = constructFromFields(fields)
		if actual != testCase.expected {
			t.Errorf("Actual parsed register from fields value is not equal to expected [%v != %v] ", actual, testCase.expected)
		}
	}
}

func TestIA32MTRCAPRegister(t *testing.T) {
	reg := registers.ParseIA32MTRRCAP(0)
	if reg.ID() != registers.IA32MTRRCAPRegisterID {
		t.Errorf("register ID %s is incorrect", reg.ID())
	}
	if reg.BitSize() != 64 {
		t.Errorf("Bit size %d is incorrect", reg.BitSize())
	}

	type parsedIA32MTRRCAP struct {
		VCNT uint8
		FIX  bool
		WC   bool
		SMRR bool
	}

	convert := func(reg registers.IA32MTRRCAP) parsedIA32MTRRCAP {
		return parsedIA32MTRRCAP{
			VCNT: reg.VariableRangeRegistersCount(),
			FIX:  reg.FixedRangedRegisteredSupported(),
			WC:   reg.WriteCombiningMemoryTypeSupported(),
			SMRR: reg.SMRRInterfaceSupported(),
		}
	}

	constructFromFields := func(field []registers.Field) parsedIA32MTRRCAP {
		return parsedIA32MTRRCAP{
			VCNT: uint8(registers.FieldValueToNumber(field[0].Value)),
			FIX:  fieldValueToBoolean(field[1].Value),
			WC:   fieldValueToBoolean(field[3].Value),
			SMRR: fieldValueToBoolean(field[4].Value),
		}
	}

	testCases := []struct {
		rawValue uint64
		expected parsedIA32MTRRCAP
	}{
		{
			rawValue: 0x2D0A,
			expected: parsedIA32MTRRCAP{
				VCNT: 0x0A,
				FIX:  true,
				WC:   true,
				SMRR: true,
			},
		},
		{
			rawValue: 0xFF,
			expected: parsedIA32MTRRCAP{
				VCNT: 0xFF,
				FIX:  false,
				WC:   false,
				SMRR: false,
			},
		},
	}

	for _, testCase := range testCases {
		mock := simpleMSRReaderMock(registers.IA32MTRRCAPRegisterOffset, testCase.rawValue)
		reg, err := registers.ReadIA32MTRRCAP(mock)
		if err != nil {
			t.Errorf("Unexpected error %v during ReadIA32FeatureControl", err)
			t.Skip()
		}

		if reg.Raw() != testCase.rawValue {
			t.Errorf("Raw() value if the register is not equal to expected [%v != %v]", reg.Raw(), testCase.rawValue)
		}

		actual := convert(reg)
		if actual != testCase.expected {
			t.Errorf("Actual parsed register value is not equal to expected [%v != %v] ", actual, testCase.expected)
		}

		fields := reg.Fields()
		if len(fields) != 6 {
			t.Errorf("Unexpected number of fields: %d ", len(fields))
			continue
		}

		actual = constructFromFields(fields)
		if actual != testCase.expected {
			t.Errorf("Actual parsed register from fields value is not equal to expected [%v != %v] ", actual, testCase.expected)
		}
	}
}

func TestIA32PlatformIDRegister(t *testing.T) {
	reg := registers.ParseIA32PlatformID(0)
	if reg.ID() != registers.IA32PlatformIDRegisterID {
		t.Errorf("register ID %s is incorrect", reg.ID())
	}
	if reg.BitSize() != 64 {
		t.Errorf("Bit size %d is incorrect", reg.BitSize())
	}

	type parsedIA32PlatformID struct {
		ProcessorFlags uint8
	}

	convert := func(reg registers.IA32PlatformID) parsedIA32PlatformID {
		return parsedIA32PlatformID{
			ProcessorFlags: reg.ProcessorFlag(),
		}
	}

	constructFromFields := func(field []registers.Field) parsedIA32PlatformID {
		return parsedIA32PlatformID{
			ProcessorFlags: uint8(registers.FieldValueToNumber(field[1].Value)),
		}
	}

	testCases := []struct {
		rawValue uint64
		expected parsedIA32PlatformID
	}{
		{
			rawValue: 0x1C000000000000,
			expected: parsedIA32PlatformID{
				ProcessorFlags: 0x7,
			},
		},
		{
			rawValue: 0x0,
			expected: parsedIA32PlatformID{
				ProcessorFlags: 0x0,
			},
		},
	}

	for _, testCase := range testCases {
		mock := simpleMSRReaderMock(registers.IA32PlatformIDRegisterOffset, testCase.rawValue)
		reg, err := registers.ReadIA32PlatformID(mock)
		if err != nil {
			t.Errorf("Unexpected error %v during ReadIA32FeatureControl", err)
			t.Skip()
		}

		if reg.Raw() != testCase.rawValue {
			t.Errorf("Raw() value if the register is not equal to expected [%v != %v]", reg.Raw(), testCase.rawValue)
		}

		actual := convert(reg)
		if actual != testCase.expected {
			t.Errorf("Actual parsed register value is not equal to expected [%v != %v]", actual, testCase.expected)
		}

		fields := reg.Fields()
		if len(fields) != 3 {
			t.Errorf("Unexpected number of fields: %d ", len(fields))
			continue
		}

		actual = constructFromFields(fields)
		if actual != testCase.expected {
			t.Errorf("Actual parsed register from fields value is not equal to expected [%v != %v] ", actual, testCase.expected)
		}
	}
}

func TestIA32DebugInterfaceRegister(t *testing.T) {
	reg := registers.ParseIA32DebugInterface(0)
	if reg.ID() != registers.IA32DebugInterfaceRegisterID {
		t.Errorf("register ID %s is incorrect", reg.ID())
	}
	if reg.BitSize() != 64 {
		t.Errorf("Bit size %d is incorrect", reg.BitSize())
	}

	type parsedIA32DebugInterface struct {
		Enabled       bool
		Locked        bool
		DebugOccurred bool
	}

	convert := func(reg registers.IA32DebugInterface) parsedIA32DebugInterface {
		return parsedIA32DebugInterface{
			Enabled:       reg.Enabled(),
			Locked:        reg.Locked(),
			DebugOccurred: reg.DebugOccurred(),
		}
	}

	constructFromFields := func(field []registers.Field) parsedIA32DebugInterface {
		return parsedIA32DebugInterface{
			Enabled:       fieldValueToBoolean(field[0].Value),
			Locked:        fieldValueToBoolean(field[2].Value),
			DebugOccurred: fieldValueToBoolean(field[3].Value),
		}
	}

	testCases := []struct {
		rawValue uint64
		expected parsedIA32DebugInterface
	}{
		{
			rawValue: 0xC0000001,
			expected: parsedIA32DebugInterface{
				Enabled:       true,
				Locked:        true,
				DebugOccurred: true,
			},
		},
		{
			rawValue: 0x0,
			expected: parsedIA32DebugInterface{
				Enabled:       false,
				Locked:        false,
				DebugOccurred: false,
			},
		},
	}

	for _, testCase := range testCases {
		mock := simpleMSRReaderMock(registers.IA32DebugInterfaceRegisterOffset, testCase.rawValue)
		reg, err := registers.ReadIA32DebugInterface(mock)
		if err != nil {
			t.Errorf("Unexpected error %v during ReadIA32FeatureControl", err)
			t.Skip()
		}

		if reg.Raw() != testCase.rawValue {
			t.Errorf("Raw() value if the register is not equal to expected [%v != %v]", reg.Raw(), testCase.rawValue)
		}

		actual := convert(reg)
		if actual != testCase.expected {
			t.Errorf("Actual parsed register value is not equal to expected [%v != %v]", actual, testCase.expected)
		}

		fields := reg.Fields()
		if len(fields) != 5 {
			t.Errorf("Unexpected number of fields: %d ", len(fields))
			continue
		}

		actual = constructFromFields(fields)
		if actual != testCase.expected {
			t.Errorf("Actual parsed register from fields value is not equal to expected [%v != %v] ", actual, testCase.expected)
		}
	}
}
