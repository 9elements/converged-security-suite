package types

// DataSource is an abstract source of byte-data.
type DataSource interface {
	Data(*State) (*Data, error)
}
