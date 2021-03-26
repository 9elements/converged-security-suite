package registers

type TPMType uint8

const (
	TPMTypeNoTpm TPMType = iota
	TPMType12
	TPMType20
	TPMTypeIntelPTT // Intel-specific implementation of integrated TPM
)
