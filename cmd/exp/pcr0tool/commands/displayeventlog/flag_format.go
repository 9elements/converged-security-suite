package displayeventlog

import (
	"flag"
	"fmt"
	"strings"
)

var _ flag.Value = (*flagFormat)(nil)

type flagFormat uint

const (
	flagFormatPlaintextOneline = flagFormat(iota)
	flagFormatPlaintextMultiline
	endOfFlagFormat
)

// String implements flag.Value.
func (f flagFormat) String() string {
	switch f {
	case flagFormatPlaintextOneline:
		return "plaintext-oneline"
	case flagFormatPlaintextMultiline:
		return "plaintext-multiline"
	}
	return fmt.Sprintf("unknown_format_%d", f)
}

// Set implements flag.Value.
func (f *flagFormat) Set(in string) error {
	in = strings.Trim(strings.ToLower(in), " ")
	for v := flagFormat(0); v < endOfFlagFormat; v++ {
		if in == v.String() {
			*f = v
			return nil
		}
	}
	return fmt.Errorf("unknown format '%s'", in)
}
