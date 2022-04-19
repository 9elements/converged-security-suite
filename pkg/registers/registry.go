package registers

import (
	"fmt"
	"reflect"
)

type registryT struct {
	idToType map[RegisterID]reflect.Type
}

var registry = registryT{
	idToType: make(map[RegisterID]reflect.Type),
}

// AddRegister remembers the register type and ID.
func (registry registryT) AddRegister(reg Register) {
	registry.idToType[reg.ID()] = reflect.TypeOf(reg)
}

// New constructs a register, given its ID and raw value. It
// will return an error if the value is of wrong underlying type.
func (registry registryT) New(regID RegisterID, value interface{}) (Register, error) {
	regT := registry.idToType[regID]
	regV := reflect.New(regT).Elem()
	if value == nil {
		return regV.Interface().(Register), nil
	}

	valV := reflect.ValueOf(value)
	switch {
	case valV.Type().ConvertibleTo(regT):
		regV.Set(valV.Convert(regT))
	case regV.Kind() == reflect.Array && regV.Type().Elem().Kind() == reflect.Uint8:
		copy(regV.Slice(0, regV.Cap()).Interface().([]byte), valV.Interface().([]byte))
	default:
		return nil, fmt.Errorf("%T is not convertible to %s", value, regT.Name())
	}
	return regV.Interface().(Register), nil
}
