package tpmeventlog

import (
	"testing"

	"github.com/9elements/converged-security-suite/v2/pkg/bootflow/subsystems/trustchains/tpm/pcr"
	"github.com/google/go-tpm/legacy/tpm2"
	"github.com/stretchr/testify/require"
)

func TestReplay(t *testing.T) {
	makeMeasurementDigest := func(alg tpm2.Algorithm, lastByteValue uint8) []byte {
		h, err := alg.Hash()
		require.NoError(t, err)
		r := make([]byte, h.Size())
		r[len(r)-1] = lastByteValue
		return r
	}

	makeFinalDigest := func(alg tpm2.Algorithm, lastByteValues []uint8) []byte {
		h, err := alg.Hash()
		require.NoError(t, err)
		final := make([]byte, h.Size())
		final[len(final)-1] = lastByteValues[0]
		extend := func(d []byte) {
			hasher := h.HashFunc().New()
			_, err = hasher.Write(final)
			require.NoError(t, err)
			_, err = hasher.Write(d)
			require.NoError(t, err)
			final = hasher.Sum(nil)
		}
		single := make([]byte, h.Size())
		for _, lastByteValue := range lastByteValues[1:] {
			single[len(single)-1] = lastByteValue
			extend(single)
		}
		return final
	}

	// An EventLog for our unit-tests would be:
	//
	// PCR # |  Algo  |         Type         |  Digest  | Data
	// ------|--------|----------------------|----------|----------------------------------
	//   0   | SHA1   | EV_NO_ACTION         | 00..0002 | []byte("StartupLocality\x00\x01")
	//   0   | SHA256 | EV_NO_ACTION         | 00..0003 | nil
	//   0   | SHA1   | EV_S_CRTM_CONTENTS   | 00..0004 | nil
	//   0   | SHA256 | EV_S_CRTM_CONTENTS   | 00..0005 | nil
	//   1   | SHA1   | EV_S_CRTM_CONTENTS   | 00..0006 | nil
	//   1   | SHA1   | EV_EFI_VARIABLE_BOOT | 00..0007 | nil
	eventLog := &TPMEventLog{
		Events: []*Event{
			{
				PCRIndex: 0,
				Type:     EV_NO_ACTION,
				Data:     []byte("StartupLocality\x00\x01"), // TPM init locality is 1
				Digest: &Digest{
					HashAlgo: tpm2.AlgSHA1,
					Digest:   makeMeasurementDigest(tpm2.AlgSHA1, 2), // on a real machine it it actually always makeMeasurementDigest(tpm2.AlgSHA1, 0)
				},
			},
			{
				PCRIndex: 0,
				Type:     EV_NO_ACTION,
				Data:     []byte("StartupLocality\x00\x01"), // TPM init locality is 1
				Digest: &Digest{
					HashAlgo: tpm2.AlgSHA256,
					Digest:   makeMeasurementDigest(tpm2.AlgSHA256, 3), // on a real machine it it actually always makeMeasurementDigest(tpm2.AlgSHA256, 0)
				},
			},
			{
				PCRIndex: 0,
				Type:     EV_S_CRTM_CONTENTS,
				Digest: &Digest{
					HashAlgo: tpm2.AlgSHA1,
					Digest:   makeMeasurementDigest(tpm2.AlgSHA1, 4),
				},
			},
			{
				PCRIndex: 0,
				Type:     EV_S_CRTM_CONTENTS,
				Digest: &Digest{
					HashAlgo: tpm2.AlgSHA256,
					Digest:   makeMeasurementDigest(tpm2.AlgSHA256, 5),
				},
			},
			{
				PCRIndex: 1,
				Type:     EV_S_CRTM_CONTENTS,
				Digest: &Digest{
					HashAlgo: tpm2.AlgSHA1,
					Digest:   makeMeasurementDigest(tpm2.AlgSHA1, 6),
				},
			},
			{
				PCRIndex: 1,
				Type:     EV_EFI_VARIABLE_BOOT,
				Digest: &Digest{
					HashAlgo: tpm2.AlgSHA1,
					Digest:   makeMeasurementDigest(tpm2.AlgSHA1, 7),
				},
			},
		},
	}

	t.Run("positive", func(t *testing.T) {
		// Validate if the replayed PCR value equals to what we expect it to be.

		for _, hashAlgo := range []tpm2.Algorithm{tpm2.AlgSHA1} {
			t.Run("pcr0", func(t *testing.T) {
				r, err := Replay(eventLog, 0, hashAlgo, nil)
				require.NoError(t, err)
				// The locality is 1, and the only measurement is 00..0004, thus: {1, 4}.
				require.Equal(t, makeFinalDigest(hashAlgo, []uint8{1, 4}), r)
			})
			t.Run("pcr1", func(t *testing.T) {
				r, err := Replay(eventLog, 1, hashAlgo, nil)
				require.NoError(t, err)
				// The init value ends with 0, and the measurements are
				// 00..0006 and 00..0007, this: {0, 6, 7}.
				require.Equal(t, makeFinalDigest(hashAlgo, []uint8{0, 6, 7}), r)
			})
		}
	})
	t.Run("negative", func(t *testing.T) {
		// Validate that Replay returns an error for all non-yet-supported PCR values.
		// This is to avoid returning wrong data to an user.

		for pcrID := pcr.ID(2); ; pcrID++ {
			for _, hashAlgo := range []tpm2.Algorithm{tpm2.AlgSHA1} {
				t.Run("not_supported/pcr%d", func(t *testing.T) {
					_, err := Replay(eventLog, pcrID, hashAlgo, nil)
					require.Error(t, err)
				})
			}
			if pcrID == 255 {
				break
			}
		}
	})
}
