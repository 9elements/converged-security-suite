package format

import (
	"fmt"
	"strings"
)

func NiceString(v any) string {
	if stringer, ok := v.(fmt.Stringer); ok {
		return stringer.String()
	}
	s := fmt.Sprintf("%#+v", v)
	w := strings.SplitN(s, ".", 2)
	return w[len(w)-1]
}

func NiceStringWithIntend(v any) string {
	var result strings.Builder
	for _, line := range strings.Split(NiceString(v), "\n") {
		result.WriteByte('\t')
		result.WriteString(line)
		result.WriteByte('\n')
	}
	return result.String()
}
