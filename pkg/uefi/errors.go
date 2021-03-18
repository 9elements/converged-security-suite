package uefi

// ErrUnableToUnwrapHPSignedFile means it was unable to find the beginning
// of the real image within the HP signed image container.
type ErrUnableToUnwrapHPSignedFile struct{}

func (err ErrUnableToUnwrapHPSignedFile) Error() string {
	return `unable to unwrap "HP signed file"`
}

type ErrZeroImage struct{}

func (err ErrZeroImage) Error() string {
	return `an empty image: it consists of zero bytes only`
}
