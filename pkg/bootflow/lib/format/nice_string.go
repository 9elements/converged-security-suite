package format

import (
	"fmt"
	"reflect"
	"strings"
)

func NiceString(v any) string {
	reflectValue := reflect.ValueOf(v)
	if reflectValue.Kind() == reflect.Pointer && reflectValue.IsNil() {
		return "<nil>"
	}
	if stringer, ok := v.(fmt.Stringer); ok {
		return stringer.String()
	}
	s := fmt.Sprintf("%#+v", v)
	w := strings.SplitN(s, ".", 2)
	return w[len(w)-1]
}

func NiceStringWithIntend(v any) string {
	reflectValue := reflect.ValueOf(v)
	if reflectValue.Kind() == reflect.Pointer && reflectValue.IsNil() {
		return "<nil>"
	}
	var result strings.Builder
	for _, line := range strings.Split(NiceString(v), "\n") {
		result.WriteByte('\t')
		result.WriteString(line)
		result.WriteByte('\n')
	}
	return result.String()
}
