package format

import "strings"

func NestedStringOf(i any) string {
	v := NiceString(i)
	return strings.ReplaceAll(strings.Trim(v, "\n"), "\n", "\n\t")
}
