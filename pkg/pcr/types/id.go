package types

import (
	"fmt"
)

// ID is a numeric identifier of a PCR register. For example PCR0 has ID == 0 and PCR8 has ID == 8.
type ID uint8

func (id ID) String() string {
	return fmt.Sprintf("PCR%d", int(id))
}
