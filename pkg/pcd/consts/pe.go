package consts

var (
	// MZSignature is the magic used to find a beginning of an portable
	// executable file
	MZSignature = []byte{0x4D, 0x5A} // See: https://en.wikipedia.org/wiki/Portable_Executable
)
