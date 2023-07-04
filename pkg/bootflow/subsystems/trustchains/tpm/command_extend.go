package tpm

import (
	"context"
	"fmt"
)

// CommandExtend implements Command to represent TPM2_PCR_Extend
//
// Is also used (together with CommandEventLogAdd) to implement a TPM2_PCR_Event Action.
type CommandExtend struct {
	PCRIndex PCRID
	HashAlgo Algorithm
	Digest   Digest
}

var _ Command = (*CommandExtend)(nil)

// NewCommandExtend returns a new instance of CommandExtend.
func NewCommandExtend(
	pcrIdx PCRID,
	hashAlgo Algorithm,
	digest Digest,
) *CommandExtend {
	return &CommandExtend{
		PCRIndex: pcrIdx,
		HashAlgo: hashAlgo,
		Digest:   digest,
	}
}

// LogString implements Command.
func (cmd CommandExtend) LogString() string {
	return fmt.Sprintf("TPMExtend(%d, %s, %s)", cmd.PCRIndex, cmd.HashAlgo, cmd.Digest)
}

// String implements fmt.Stringer.
func (cmd CommandExtend) String() string {
	return cmd.LogString()
}

// apply implements Command.
func (cmd *CommandExtend) Apply(_ context.Context, tpm *TPM) error {
	hasher, err := acquireHasher(cmd.HashAlgo)
	if err != nil {
		return fmt.Errorf("invalid hash algo: %w", err)
	}
	defer releaseHasher(hasher)

	pcrValue, err := tpm.PCRValues.Get(cmd.PCRIndex, cmd.HashAlgo)
	if err != nil {
		return fmt.Errorf("unable to get the PCR value: %w", err)
	}
	if _, err := hasher.Write(pcrValue); err != nil {
		return fmt.Errorf("unable to write into hasher %T the original value: %w", hasher, err)
	}
	if _, err := hasher.Write(cmd.Digest); err != nil {
		return fmt.Errorf("unable to write into hasher %T the given value: %w", hasher, err)
	}
	{
		// To avoid memory allocation we pass the existing slice as the buffer to write to.
		//
		// This works only if the length of the buffer is not smaller than the required size:
		if len(pcrValue) != hasher.Size() {
			return fmt.Errorf("internal error: should never happen: %d != %d", len(pcrValue), hasher.Size())
		}
		pcrValueResult := hasher.Sum(pcrValue[:0])

		// Rechecking just in case that everything works as expected:
		if err := assertSameSlice(pcrValue, pcrValueResult); err != nil {
			return fmt.Errorf("internal error: should never happen: %w", err)
		}
	}
	return nil
}
