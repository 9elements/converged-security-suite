package types

type DataSource interface {
	Data(*State) (*Data, error)
}
