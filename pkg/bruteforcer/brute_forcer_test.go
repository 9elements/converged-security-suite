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
	l := sync.Mutex{}
	m := map[uint64]struct{}{}
	maxDistance := 4
	b := make([]byte, 4)
	result, err := BruteForceBytes(b, uint64(maxDistance), nil, func(_ interface{}, data []byte) bool {
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
	}, 0)
	require.Nil(t, result)
	require.Nil(t, err)

	amountOfCombinations := calcAmountOfCombinations(len(b)*8, maxDistance)
	require.Len(t, m, int(amountOfCombinations), fmt.Sprintf("%d != %d", len(m), amountOfCombinations))
}

func BenchmarkBruteForce(b *testing.B) {
	for _, checkFuncName := range []string{"noop", "sha1.Sum"} {
		var checkFunc CheckFunc
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
			for distance := 1; distance <= 6; distance++ {
				b.Run(fmt.Sprintf("distance_%d", distance), func(b *testing.B) {
					for dataSize := 1; dataSize <= 8; dataSize++ {
						b.Run(fmt.Sprintf("dataSize_%d", dataSize), func(b *testing.B) {
							data := make([]byte, dataSize)
							b.ReportAllocs()
							b.ResetTimer()
							for i := 0; i < b.N; i++ {
								_, _ = BruteForceBytes(data, uint64(distance), nil, checkFunc, 0)
							}
						})
					}
				})
			}
		})
	}
}
