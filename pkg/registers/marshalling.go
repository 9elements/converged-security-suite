package registers

import (
	"bytes"
	"encoding/binary"
	"fmt"
)

// MarshalValue puts register's internal value into a sequence of bytes
func MarshalValue(reg Register) ([]byte, error) {
	if reg == nil {
		return nil, fmt.Errorf("input register is nil")
	}
	switch r := reg.(type) {
	case RawRegister:
		return r.Raw(), nil
	case RawRegister8:
		return []byte{r.Raw()}, nil
	case RawRegister16:
		b := make([]byte, 2)
		binary.LittleEndian.PutUint16(b, r.Raw())
		return b, nil
	case RawRegister32:
		b := make([]byte, 4)
		binary.LittleEndian.PutUint32(b, r.Raw())
		return b, nil
	case RawRegister64:
		b := make([]byte, 8)
		binary.LittleEndian.PutUint64(b, r.Raw())
		return b, nil
	}
	return nil, fmt.Errorf("input register doesn't support any raw accessor interface")
}

func getRegister64Parser(regID RegisterID) func(ui64 uint64) Register {
	switch regID {
	case BootGuardPBECRegisterID:
		return func(ui64 uint64) Register {
			return ParseBootGuardPBEC(ui64)
		}
	case BTGSACMInfoRegisterID:
		return func(ui64 uint64) Register {
			return ParseBTGSACMInfo(ui64)
		}
	case IA32DebugInterfaceRegisterID:
		return func(ui64 uint64) Register {
			return ParseIA32DebugInterface(ui64)
		}
	case IA32FeatureControlRegisterID:
		return func(ui64 uint64) Register {
			return ParseIA32FeatureControl(ui64)
		}
	case IA32MTRRCAPRegisterID:
		return func(ui64 uint64) Register {
			return ParseIA32MTRRCAP(ui64)
		}
	case IA32PlatformIDRegisterID:
		return func(ui64 uint64) Register {
			return ParseIA32PlatformID(ui64)
		}
	case IA32SMRRPhysBaseRegisterID:
		return func(ui64 uint64) Register {
			return ParseIA32SMRRPhysBase(ui64)
		}
	case IA32SMRRPhysMaskRegisterID:
		return func(ui64 uint64) Register {
			return ParseIA32SMRRPhysMask(ui64)
		}
	case AcmPolicyStatusRegisterID:
		return func(ui64 uint64) Register {
			return ParseACMPolicyStatusRegister(ui64)
		}
	case ACMStatusRegisterID:
		return func(ui64 uint64) Register {
			return ParseACMStatusRegister(ui64)
		}
	case TXTBootStatusRegisterID:
		return func(ui64 uint64) Register {
			return ParseTXTBootStatus(ui64)
		}
	case TXTDeviceIDRegisterID:
		return func(ui64 uint64) Register {
			return ParseTXTDeviceID(ui64)
		}
	case TXTStatusRegisterID:
		return func(ui64 uint64) Register {
			return ParseTXTStatus(ui64)
		}
	}
	return nil
}

func getRegister32Parser(regID RegisterID) func(ui32 uint32) Register {
	switch regID {
	case TXTVerFSBIfRegisterID, TXTVerEMIfRegisterID, TXTSINITBaseRegisterID, TXTSINITSizeRegisterID,
		TXTMLEJoinRegisterID, TXTHeapBaseRegisterID, TXTHeapSizeRegisterID:
		return func(ui32 uint32) Register {
			return &simpleRegister32{
				id:    regID,
				Value: ui32,
			}
		}
	case TXTDMAProtectedRangeRegisterID:
		return func(ui32 uint32) Register {
			return ParseTXTDMAProtectedRangeRegister(ui32)
		}
	}
	return nil
}

func getRegister8Parser(regID RegisterID) func(ui8 uint8) Register {
	switch regID {
	case TXTErrorCodeRegisterID:
		return func(ui8 uint8) Register {
			return ParseTXTErrorCode(ui8)
		}
	case TXTErrorStatusRegisterID:
		return func(ui8 uint8) Register {
			return ParseTXTErrorStatus(ui8)
		}
	}
	return nil
}

// Unmarshal constructs register from it's id and marshalled value
func Unmarshal(id RegisterID, b []byte) (Register, error) {
	// special case registers
	switch id {
	case TXTPublicKeyRegisterID:
		if len(b) != 32 {
			return nil, fmt.Errorf("incorrect input bytes length, 32 is expected, but got %d", len(b))
		}
		var arr [32]byte
		copy(arr[:], b[:])
		return ParseTXTPublicKey(arr), nil
	}

	buf := bytes.NewReader(b)

	parser64 := getRegister64Parser(id)
	if parser64 != nil {
		var ui64 uint64
		if err := binary.Read(buf, binary.LittleEndian, &ui64); err != nil {
			return nil, err
		}
		return parser64(ui64), nil
	}

	parser32 := getRegister32Parser(id)
	if parser32 != nil {
		var ui32 uint32
		if err := binary.Read(buf, binary.LittleEndian, &ui32); err != nil {
			return nil, err
		}
		return parser32(ui32), nil
	}

	parser8 := getRegister8Parser(id)
	if parser8 != nil {
		var ui8 uint8
		if err := binary.Read(buf, binary.LittleEndian, &ui8); err != nil {
			return nil, err
		}
		return parser8(ui8), nil
	}

	return nil, fmt.Errorf("unknown register id %s", id)
}
