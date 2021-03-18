package registers_test

import (
	"testing"

	"github.com/9elements/converged-security-suite/v2/pkg/hwapi"
	"github.com/9elements/converged-security-suite/v2/pkg/registers"
)

func TestTXT(t *testing.T) {
	txtAPI := hwapi.GetPcMock(func(addr uint64) byte { return hwapi.MockPCReadMemory(addr) })

	got, err := registers.FetchTXTConfigSpace(txtAPI)
	if err != nil {
		t.Errorf("FetchTXTConfigSpace() failed: %v", err)
	}

	t.Logf("TXT: %+v", got)
}

func TestReadTXTRegisters(t *testing.T) {
	txtAPI := hwapi.GetPcMock(func(addr uint64) byte { return hwapi.MockPCReadMemory(addr) })

	data, err := registers.FetchTXTConfigSpace(txtAPI)
	if err != nil {
		t.Errorf("FetchTXTConfigSpace() failed: %v", err)
		t.Skip()
	}

	txtRegisters, err := registers.ReadTXTRegisters(data)
	if err != nil {
		t.Errorf("ParseTXTRegs() failed: %v", err)
		t.Skip()
	}

	t.Run("no_duplicates", func(t *testing.T) {
		allIDs := make(map[registers.RegisterID]struct{})
		for _, reg := range txtRegisters {
			if reg == nil {
				t.Errorf("A nil register is found")
				t.Skip()
			}

			foundReg := txtRegisters.Find(reg.ID())
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
		for _, reg := range txtRegisters {
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

		checkIsFound(wrapResult(registers.FindACMPolicyStatus(txtRegisters)), "ACMPolicyStatus")
		checkIsFound(wrapResult(registers.FindACMStatus(txtRegisters)), "ACMStatus")
		checkIsFound(wrapResult(registers.FindTXTBootStatus(txtRegisters)), "TXTBootStatus")
		checkIsFound(wrapResult(registers.FindTXTDeviceID(txtRegisters)), "TXTDeviceID")
		checkIsFound(wrapResult(registers.FindTXTDMAProtectedRange(txtRegisters)), "TXTDMAProtectedRange")
		checkIsFound(wrapResult(registers.FindTXTErrorCode(txtRegisters)), "TXTErrorCode")
		checkIsFound(wrapResult(registers.FindTXTPublicKey(txtRegisters)), "TXTPublicKey")
		checkIsFound(wrapResult(registers.FindTXTStatus(txtRegisters)), "TXTStatus")
		checkIsFound(wrapResult(registers.FindTXTVerFSBIf(txtRegisters)), "TXTVerFSBIf")
		checkIsFound(wrapResult(registers.FindTXTVerEMIf(txtRegisters)), "TXTVerEMIf")
		checkIsFound(wrapResult(registers.FindTXTSInitBase(txtRegisters)), "TXTSInitBase")
		checkIsFound(wrapResult(registers.FindTXTSInitSize(txtRegisters)), "TXTSInitSize")
		checkIsFound(wrapResult(registers.FindTXTMLEJoin(txtRegisters)), "TXTMLEJoin")
		checkIsFound(wrapResult(registers.FindTXTHeapBase(txtRegisters)), "TXTHeapBase")
		checkIsFound(wrapResult(registers.FindTXTHeapSize(txtRegisters)), "TXTHeapSize")
	})
}

func TestTXTErrorStatus(t *testing.T) {
	txtErrorStatus := registers.ParseTXTErrorStatus(0)
	if txtErrorStatus.ID() != registers.TXTErrorStatusRegisterID {
		t.Errorf("Incorrect ID, expected: %v, actual: %v", registers.TXTErrorStatusRegisterID, txtErrorStatus.ID())
	}
	if txtErrorStatus.BitSize() != 8 {
		t.Errorf("Incorrect BitSize, expected: 64. actual: %v", txtErrorStatus.BitSize())
	}

	type parsedErrorStatus struct {
		reset bool
	}

	convert := func(reg registers.TXTErrorStatus) parsedErrorStatus {
		return parsedErrorStatus{
			reset: reg.Reset(),
		}
	}

	constructFromFields := func(field []registers.Field) parsedErrorStatus {
		return parsedErrorStatus{
			reset: fieldValueToBoolean(field[0].Value),
		}
	}
	testCases := []struct {
		registerValue uint8
		expected      parsedErrorStatus
	}{
		{
			registerValue: 0xF0,
			expected: parsedErrorStatus{
				reset: false,
			},
		},
		{
			registerValue: 0xF1,
			expected: parsedErrorStatus{
				reset: true,
			},
		},
	}

	for _, testCase := range testCases {
		txtAPI := hwapi.GetPcMock(func(addr uint64) byte {
			if addr == registers.TxtPublicSpace+registers.TXTErrorStatusRegisterOffset {
				return testCase.registerValue
			}
			return hwapi.MockPCReadMemory(addr)
		})

		data, err := registers.FetchTXTConfigSpace(txtAPI)
		if err != nil {
			t.Errorf("ParseTXTRegs() failed: %v", err)
			t.Skip()
		}

		reg, err := registers.ReadTXTErrorStatusRegister(data)
		if err != nil {
			t.Errorf("ReadTXTErrorStatusRegister() failed: %v", err)
			t.Skip()
		}

		if reg.Raw() != testCase.registerValue {
			t.Errorf("Raw values do not match, actual: %d, expected: %d", reg.Raw(), testCase.registerValue)
		}

		actual := convert(reg)
		expected := testCase.expected
		if actual != expected {
			t.Errorf("Result missmatch: got %v, want %v", actual, expected)
		}

		fields := reg.Fields()
		if len(fields) != 2 {
			t.Errorf("Fields count missmatch: got %v, want %v", len(fields), 23)
			continue
		}

		actual = constructFromFields(fields)
		if actual != expected {
			t.Errorf("Result missmatch for fields: got %v, want %v", actual, expected)
		}
	}
}

func TestACMPolicyStatus(t *testing.T) {
	type parsedACMPolicyStatus struct {
		KMID                  uint8
		BootPolicyM           bool
		BootPolicyV           bool
		BootPolicyHAP         bool
		BootPolicyT           bool
		BootPolicyDCD         bool
		BootPolicyDBI         bool
		BootPolicyPBE         bool
		TPMType               registers.TPMType
		TPMSuccess            bool
		BackupAction          registers.BackupAction
		TXTProfileSelection   uint8
		MemoryScrubbingPolicy registers.MemoryScrubbingPolicy
		IBBDmaProtection      bool
		SCRTMStatus           registers.SCRTMStatus
		CPUCoSigningEnabled   bool
		TPMStartupLocality    registers.TPMStartupLocality
	}

	convert := func(reg registers.ACMPolicyStatus) parsedACMPolicyStatus {
		return parsedACMPolicyStatus{
			KMID:                  reg.KMID(),
			BootPolicyM:           reg.BootPolicyM(),
			BootPolicyV:           reg.BootPolicyV(),
			BootPolicyHAP:         reg.BootPolicyHAP(),
			BootPolicyT:           reg.BootPolicyT(),
			BootPolicyDCD:         reg.BootPolicyDCD(),
			BootPolicyDBI:         reg.BootPolicyDBI(),
			BootPolicyPBE:         reg.BootPolicyPBE(),
			TPMType:               reg.TPMType(),
			TPMSuccess:            reg.TPMSuccess(),
			BackupAction:          reg.BackupAction(),
			TXTProfileSelection:   reg.TXTProfileSelection(),
			MemoryScrubbingPolicy: reg.MemoryScrubbingPolicy(),
			IBBDmaProtection:      reg.IBBDmaProtection(),
			SCRTMStatus:           reg.SCRTMStatus(),
			CPUCoSigningEnabled:   reg.CPUCoSigningEnabled(),
			TPMStartupLocality:    reg.TPMStartupLocality(),
		}
	}

	toStartupLocality := func(v uint64) registers.TPMStartupLocality {
		if v == 0 {
			return registers.TPMStartupLocality3
		}
		return registers.TPMStartupLocality0
	}

	constructFromFields := func(field []registers.Field) parsedACMPolicyStatus {
		if len(field) < 23 {
			panic("Insufficient number of fields to construct ACMPolicyStatus")
		}
		return parsedACMPolicyStatus{
			KMID:          uint8(registers.FieldValueToNumber(field[0].Value)),
			BootPolicyM:   fieldValueToBoolean(field[1].Value),
			BootPolicyV:   fieldValueToBoolean(field[2].Value),
			BootPolicyHAP: fieldValueToBoolean(field[3].Value),
			BootPolicyT:   fieldValueToBoolean(field[4].Value),
			// 5 is reserved
			BootPolicyDCD: fieldValueToBoolean(field[6].Value),
			BootPolicyDBI: fieldValueToBoolean(field[7].Value),
			BootPolicyPBE: fieldValueToBoolean(field[8].Value),
			// 9 is reserved
			TPMType:    registers.TPMType(registers.FieldValueToNumber(field[10].Value)),
			TPMSuccess: fieldValueToBoolean(field[11].Value),
			// 12 is reserved
			BackupAction:          registers.BackupAction(registers.FieldValueToNumber(field[13].Value)),
			TXTProfileSelection:   uint8(registers.FieldValueToNumber(field[14].Value)),
			MemoryScrubbingPolicy: registers.MemoryScrubbingPolicy(registers.FieldValueToNumber(field[15].Value)),
			// 16 is reserved
			IBBDmaProtection: fieldValueToBoolean(field[17].Value),
			// 18 is reserved
			SCRTMStatus:         registers.SCRTMStatus(registers.FieldValueToNumber(field[19].Value)),
			CPUCoSigningEnabled: fieldValueToBoolean(field[20].Value),
			TPMStartupLocality:  toStartupLocality(registers.FieldValueToNumber(field[21].Value)),
			// 22 is reserved
		}
	}

	testCases := []struct {
		registerValue [8]byte
		expected      parsedACMPolicyStatus
	}{
		{
			registerValue: [8]byte{0x81, 0x80, 0x10, 0x00, 0x02, 0x00, 0x00, 0x00},
			expected: parsedACMPolicyStatus{
				KMID:                  1,
				BootPolicyM:           false,
				BootPolicyV:           false,
				BootPolicyHAP:         false,
				BootPolicyT:           true,
				BootPolicyDCD:         false,
				BootPolicyDBI:         false,
				BootPolicyPBE:         false,
				TPMType:               registers.TPMTypeNoTpm,
				TPMSuccess:            true,
				BackupAction:          registers.BackupActionMemoryPowerDown,
				TXTProfileSelection:   1,
				MemoryScrubbingPolicy: registers.MemoryScrubbingPolicyDefault,
				IBBDmaProtection:      false,
				SCRTMStatus:           registers.SCRTMStatusTXT,
				CPUCoSigningEnabled:   false,
				TPMStartupLocality:    registers.TPMStartupLocality3,
			},
		},
	}

	acmPolicyStatus := registers.ParseACMPolicyStatusRegister(0)
	if acmPolicyStatus.ID() != registers.AcmPolicyStatusRegisterID {
		t.Errorf("Incorrect ID, expected: %v, actual: %v", registers.AcmPolicyStatusRegisterID, acmPolicyStatus.ID())
	}

	if acmPolicyStatus.BitSize() != 64 {
		t.Errorf("Incorrect BitSize, expected: 64. actual: %v", acmPolicyStatus.BitSize())
	}

	for _, testCase := range testCases {
		txtAPI := hwapi.GetPcMock(func(addr uint64) byte {
			if addr >= (registers.TxtPublicSpace+registers.ACMPolicyStatusRegisterOffset) &&
				addr < uint64(registers.TxtPublicSpace+registers.ACMPolicyStatusRegisterOffset+len(testCase.registerValue)) {
				idx := addr - (registers.TxtPublicSpace + registers.ACMPolicyStatusRegisterOffset)
				return testCase.registerValue[idx]
			}
			return hwapi.MockPCReadMemory(addr)
		})

		data, err := registers.FetchTXTConfigSpace(txtAPI)
		if err != nil {
			t.Errorf("ParseTXTRegs() failed: %v", err)
			t.Skip()
		}

		reg, err := registers.ReadACMPolicyStatusRegister(data)
		if err != nil {
			t.Errorf("ReadACMPolicyStatusRegister() failed: %v", err)
			t.Skip()
		}

		actual := convert(reg)
		expected := testCase.expected
		if actual != expected {
			t.Errorf("Result missmatch: got %v, want %v", actual, expected)
		}

		fields := reg.Fields()
		if len(fields) != 23 {
			t.Errorf("Fields count missmatch: got %v, want %v", len(fields), 23)
			continue
		}

		actual = constructFromFields(fields)
		if actual != expected {
			t.Errorf("Result missmatch for fields: got %v, want %v", actual, expected)
		}
	}
}

func TestReadACMStatus(t *testing.T) {
	type acmStatusParsed struct {
		valid          bool
		minorErrorCode uint16
		acmStarted     bool
		majorErrorCode uint8
		classCode      uint8
		moduleType     uint8
	}

	convert := func(reg registers.ACMStatus) acmStatusParsed {
		return acmStatusParsed{
			valid:          reg.Valid(),
			minorErrorCode: reg.MinorErrorCode(),
			acmStarted:     reg.ACMStarted(),
			majorErrorCode: reg.MajorErrorCode(),
			classCode:      reg.ClassCode(),
			moduleType:     reg.ModuleType(),
		}
	}

	type fields struct {
		ACMStatus [4]byte
	}

	tests := []struct {
		name          string
		fields        fields
		wantErr       bool
		wantACMStatus acmStatusParsed
	}{
		{
			"Invalid register",
			fields{[4]byte{0, 0, 0, 0}},
			false,
			acmStatusParsed{
				false,
				0,
				false,
				0,
				0,
				0,
			},
		},
		{
			"Valid register",
			fields{[4]byte{0, 0, 0, 0x80}},
			false,
			acmStatusParsed{
				true,
				0,
				false,
				0,
				0,
				0,
			},
		},
		{
			"Minor error",
			fields{[4]byte{0, 0, 0xaa, 0x8b}},
			false,
			acmStatusParsed{
				true,
				0xbaa,
				false,
				0,
				0,
				0,
			},
		},
		{
			"Major error",
			fields{[4]byte{0, 0xc, 0x00, 0x80}},
			false,
			acmStatusParsed{
				true,
				0,
				false,
				0x3,
				0,
				0,
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			txtAPI := hwapi.GetPcMock(func(addr uint64) byte {
				if addr >= (registers.TxtPublicSpace+registers.ACMStatusRegisterOffset) && addr < uint64(registers.TxtPublicSpace+registers.ACMStatusRegisterOffset+len(tt.fields.ACMStatus)) {
					idx := addr - (registers.TxtPublicSpace + registers.ACMStatusRegisterOffset)
					t.Logf("%x\n", tt.fields.ACMStatus[idx])
					return tt.fields.ACMStatus[idx]
				}
				return hwapi.MockPCReadMemory(addr)
			})

			data, err := registers.FetchTXTConfigSpace(txtAPI)
			if err != nil {
				t.Errorf("FetchTXTConfigSpace() failed: %v", err)
				t.Skip()
			}
			got, err := registers.ReadACMStatusRegister(data)
			if err != nil && !tt.wantErr {
				t.Errorf("ReadACMStatus() failed, got unexpected error: %v", err)
			}
			if err == nil && tt.wantErr {
				t.Errorf("ReadACMStatus() failed, expected an error")
			}
			actual := convert(got)
			if actual != tt.wantACMStatus {
				t.Errorf("Result missmatch: got %v, want %v", actual, tt.wantACMStatus)
			}
		})
	}
}
