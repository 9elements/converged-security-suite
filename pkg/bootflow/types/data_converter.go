package types

type DataConverter interface {
	Convert([]byte) []byte
}
