package cbnt

// CMOSIoAddress holds information about the location of on-demand power down requests in CMOS.
// The structure is a substructure used in PowerDownRequest structure.
type CMOSIoAddress struct {
	MediaType            uint8
	IndexRegisterAddress uint16
	DataRegisterAddress  uint16
	BitFieldWidth        uint8
	BitFieldPosition     uint8
	IndexOffset          uint8
}

// TPMNvAddress holds information about the location of on-demand power down requests in TPM NVRAM.
// The structure is a substructure used in PowerDownRequest structure.
type TPMNvAddress struct {
	MediaType        uint8
	NVIndex          uint32
	BitFieldWidth    uint8
	BitFieldPosition uint8
	IndexOffset      uint8
}

// PowerDownRequest holds information of the storage location for the on-demand power down variable.
// Field: PDReqMedia holds an union of 1 CMOSIoAddress or array of 1:3 TPMNvAddress
type PowerDownRequest struct {
	ID         uint64 `default:"0x5F5F504452535F5F"`
	Version    uint8  `default:"0x10"`
	SizeOfData uint16 `default:"0"`
	Reserved   uint8  `default:"0"`
	PDReqMedia []byte
}

// Pcr0Data represents the data hashed into PCR0 of the TPM by S-ACM
type Pcr0Data struct {
	ACMPolicyStatus uint64
	ACMSVN          uint16
	ACMSignature    []byte
	KMSignature     []byte
	BPMSignature    []byte
	BPMIBBDigest    []byte
}

// Pcr7Data represents the data hashed into PCR7 of the TPM by S-ACM optionally
type Pcr7Data struct {
	ACMPolicyStatus uint64
	ACMSVN          uint16
	ACMKeyHash      [32]byte
	BPMKey          [32]byte
	BPMKeyHash      []byte
}
