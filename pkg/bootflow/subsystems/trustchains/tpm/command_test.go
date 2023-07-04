package tpm

import (
	"context"
	"crypto/sha256"
	"fmt"
	"testing"

	"github.com/facebookincubator/go-belt/tool/logger"
	"github.com/facebookincubator/go-belt/tool/logger/implementation/logrus"
	"github.com/google/go-tpm/tpm2"
	"github.com/stretchr/testify/require"
)

func BenchmarkCommandsApply(b *testing.B) {
	ctx := logger.CtxWithLogger(context.Background(), logrus.Default())
	tpmInstance := NewTPM()
	log := make(Commands, 1000)
	log[0] = &CommandInit{}
	for idx := 1; idx < len(log); idx++ {
		log[idx] = &CommandExtend{
			PCRIndex: 0,
			HashAlgo: 0,
			Digest:   make([]byte, sha256.Size),
		}
	}
	for _, hashAlgo := range []tpm2.Algorithm{tpm2.AlgSHA1, tpm2.AlgSHA256} {
		h, err := hashAlgo.Hash()
		require.NoError(b, err)
		for idx := 1; idx < len(log); idx++ {
			cmd := log[idx].(*CommandExtend)
			cmd.HashAlgo = hashAlgo
			cmd.Digest = cmd.Digest[:h.Size()]
		}
		b.Run(hashAlgo.String(), func(b *testing.B) {
			for _, logSize := range []uint{0, 1, 10, 100, 1000} {
				b.Run(fmt.Sprintf("logSize-%d", logSize), func(b *testing.B) {
					b.ReportAllocs()
					b.ResetTimer()
					for i := 0; i < b.N; i++ {
						tpmInstance.DoNotUse_ResetNoInit()
						err := log[:logSize].Apply(ctx, tpmInstance)
						require.NoError(b, err)
					}
				})
			}
		})
	}
}
