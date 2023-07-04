package types

// DataConverter is an abstract converter of data. For example SHA1 hasher is a data converter.
type DataConverter interface {
	Convert(RawBytes) ConvertedBytes
}

// DataConverterFactory is a factory of DataConverter.
type DataConverterFactory interface {
	NewDataConverter() DataConverter
}
