package registers

import (
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"reflect"
	"strconv"
	"strings"
)

func valueToHex(vRaw interface{}) string {
	v := reflect.ValueOf(vRaw)
	switch {
	case v.Type().ConvertibleTo(reflect.TypeOf(uint64(0))):
		i := v.Convert(reflect.TypeOf(uint64(0))).Interface().(uint64)
		return "0x" + strconv.FormatUint(i, 16)
	case v.Type().ConvertibleTo(reflect.TypeOf([]byte(nil))):
		b := v.Convert(reflect.TypeOf([]byte(nil))).Interface().([]byte)
		return "0x" + hex.EncodeToString(b)
	}
	panic(fmt.Sprintf("unknown type: %T", vRaw))
}

func valueUnpack(regID RegisterID, v interface{}) (interface{}, error) {
	switch v := v.(type) {
	case uint8, uint16, uint32, uint64, uint, int:
		return v, nil
	case string:
		return valueUnpackString(regID, v)
	default:
		return nil, fmt.Errorf("unknown value type: %T", v)
	}
}

func valueUnpackString(regID RegisterID, s string) (interface{}, error) {
	switch {
	case strings.HasPrefix(s, "0x"):
		return valueFromHex(regID, s[2:])
	case strings.HasPrefix(s, "base64:"): // TODO: obsolete format, remove it
		return valueFromBase64(regID, s[7:])
	default:
		return nil, fmt.Errorf("unknown prefix in string: '%s'", s)
	}
}

func valueFromHex(regID RegisterID, h string) (interface{}, error) {
	regSample, err := registry.New(regID, nil)
	if err != nil {
		return nil, fmt.Errorf("unable to create a value for register %v: %w", regID, err)
	}
	v := reflect.New(reflect.TypeOf(regSample.Value())).Elem()
	switch {
	case v.Type().ConvertibleTo(reflect.TypeOf(uint64(0))):
		i, err := strconv.ParseUint(h, 16, int(v.Type().Size())*8)
		if err != nil {
			return nil, fmt.Errorf("unable to parse hex '%s' to int: %w", h, err)
		}
		v.SetUint(i)
	case v.Type().ConvertibleTo(reflect.TypeOf([]byte(nil))):
		b, err := hex.DecodeString(h)
		if err != nil {
			return nil, fmt.Errorf("invalid hex '%s': %w", h, err)
		}
		v.SetBytes(b)
	default:
		return nil, fmt.Errorf("unknown type: %T", regSample)
	}
	return v.Interface(), nil
}

// TODO: delete this function
func valueFromBase64(regID RegisterID, b64 string) (interface{}, error) {
	b, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		return nil, fmt.Errorf("unable to decode base64 string '%s': %w", b64, err)
	}
	return ValueFromBytes(regID, b)
}
