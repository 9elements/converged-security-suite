package bruteforcer

import (
	"crypto/sha1"
	"encoding/binary"
	"fmt"
	"sync"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestBruteForce(t *testing.T) {
	t.Run("Bytes", func(t *testing.T) {
		l := sync.Mutex{}
		m := map[uint64]struct{}{}
		maxDistance := 4
		b := make([]byte, 4)
		result, err := BruteForce(b, 8, 0, uint64(maxDistance), nil, func(_ any, data []byte) bool {
			l.Lock()
			defer l.Unlock()
			buf := make([]byte, 8)
			copy(buf, data)
			key := binary.LittleEndian.Uint64(buf)
			if _, ok := m[key]; ok {
				t.Fail()
			}
			m[key] = struct{}{}
			return false
		}, ApplyBitFlipsBytes, 0)
		require.Nil(t, result)
		require.Nil(t, err)

		amountOfCombinations := calcAmountOfCombinations(len(b)*8, maxDistance)
		require.Len(t, m, int(amountOfCombinations), fmt.Sprintf("%d != %d", len(m), amountOfCombinations))
	})

	t.Run("Bools", func(t *testing.T) {
		b := []bool{true, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, true, true, true, true, true, false, true, false, false}
		result, err := BruteForce(b, 1, 0, 5, nil, func(_ any, data []bool) bool {
			return false
		}, ApplyBitFlipsBools, 0)
		require.Nil(t, result)
		require.Nil(t, err)
	})
}

func BenchmarkBruteForce(b *testing.B) {
	for _, checkFuncName := range []string{"noop", "sha1.Sum"} {
		var checkFunc CheckFunc[byte]
		switch checkFuncName {
		case "noop":
			checkFunc = func(_ interface{}, data []byte) bool {
				return false
			}
		case "sha1.Sum":
			checkFunc = func(_ interface{}, data []byte) bool {
				sha1.Sum(data)
				return false
			}
		default:
			panic(checkFuncName)
		}
		b.Run(checkFuncName, func(b *testing.B) {
			for minDistance := 1; minDistance <= 6; minDistance++ {
				b.Run(fmt.Sprintf("minDistance_%d", minDistance), func(b *testing.B) {
					for maxDistance := minDistance; maxDistance <= 6; maxDistance++ {
						b.Run(fmt.Sprintf("maxDistance_%d", maxDistance), func(b *testing.B) {
							for dataSize := 1; dataSize <= 8; dataSize++ {
								b.Run(fmt.Sprintf("dataSize_%d", dataSize), func(b *testing.B) {
									data := make([]byte, dataSize)
									b.ReportAllocs()
									b.ResetTimer()
									for i := 0; i < b.N; i++ {
										_, _ = BruteForce(data, 8, uint64(minDistance), uint64(maxDistance), nil, checkFunc, ApplyBitFlipsBytes, 0)
									}
								})
							}
						})
					}
				})
			}
		})
	}
}
