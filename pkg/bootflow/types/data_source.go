package types

import "context"

// DataSource is an abstract source of byte-data.
type DataSource interface {
	Data(context.Context, *State) (*Data, error)
}
