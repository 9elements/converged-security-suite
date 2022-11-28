package tpm

import (
	"context"
	"fmt"

	"github.com/google/go-tpm/tpm2"
)

type CommandExtend struct {
	PCRIndex PCRID
	HashAlgo tpm2.Algorithm
	Digest   Digest
}

var _ Command = (*CommandExtend)(nil)

func NewCommandExtend(
	pcrIdx PCRID,
	hashAlgo tpm2.Algorithm,
	digest Digest,
) *CommandExtend {
	return &CommandExtend{
		PCRIndex: pcrIdx,
		HashAlgo: hashAlgo,
		Digest:   digest,
	}
}

func (cmd *CommandExtend) LogString() string {
	return fmt.Sprintf("TPMExtend(%d, %s, %X)", cmd.PCRIndex, cmd.HashAlgo, cmd.Digest)
}

func (cmd *CommandExtend) GoString() string {
	return cmd.LogString()
}

func (cmd *CommandExtend) apply(_ context.Context, tpm *TPM) error {
	h, err := cmd.HashAlgo.Hash()
	if err != nil {
		return fmt.Errorf("invalid hash algo: %w", err)
	}
	hasher := h.New()

	oldValue, err := tpm.PCRValues.Get(cmd.PCRIndex, cmd.HashAlgo)
	if err != nil {
		return fmt.Errorf("unable to get the PCR value: %w", err)
	}
	if _, err := hasher.Write(oldValue); err != nil {
		return fmt.Errorf("unable to write into hasher %T the original value: %w", hasher, err)
	}
	if _, err := hasher.Write(cmd.Digest); err != nil {
		return fmt.Errorf("unable to write into hasher %T the given value: %w", hasher, err)
	}
	newValue := hasher.Sum(nil)
	if err := tpm.PCRValues.Set(cmd.PCRIndex, cmd.HashAlgo, newValue); err != nil {
		return fmt.Errorf("unable to update the PCR value: %w", err)
	}
	return nil
}
