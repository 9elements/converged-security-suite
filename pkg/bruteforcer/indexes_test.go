package bruteforcer

import (
	"fmt"
	"math"
	"math/big"
	"math/rand"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestGetCombinationID(t *testing.T) {
	iter := NewUniqueUnorderedCombinationIterator(3, 70)
	amountOfCombinations := uint64(binomialCoefficient(70, 3))
	for combinationID := uint64(0); combinationID < amountOfCombinations; combinationID++ {
		require.Equal(t, combinationID, iter.GetCombinationID())
		iter.Next()
	}
}

func TestSetGetCombinationID(t *testing.T) {
	rand.Seed(0)
	iter := NewUniqueUnorderedCombinationIterator(10, 70)
	amountOfCombinations := uint64(binomialCoefficient(70, 10))
	for i := 0; i < 100; i++ {
		combinationID := rand.Uint64() % amountOfCombinations
		iter.SetCombinationID(combinationID)
		require.Equal(t, combinationID, iter.GetCombinationID())
		iter.Next()
	}
}

func TestAmountOfCombinations(t *testing.T) {
	iter := NewUniqueUnorderedCombinationIterator(10, 70)
	require.Equal(t, uint64(binomialCoefficient(71, 10)), iter.AmountOfCombinations())
}

func calcAmountOfCombinations(valueLimit, maxDistance int) int64 {
	totalExpectedSize := int64(0)
	for distance := 0; distance <= maxDistance; distance++ {
		// See https://en.wikipedia.org/wiki/Combination#Number_of_k-combinations
		expectedSize := binomialCoefficient(valueLimit, distance)

		totalExpectedSize += expectedSize
	}

	return totalExpectedSize
}

func binomialCoefficient(n, k int) int64 {
	v := big.NewInt(1).Binomial(int64(n), int64(k))
	if v.Cmp(big.NewInt(math.MaxInt64)) > 0 {
		panic("overflow")
	}
	return v.Int64()
}

func BenchmarkInitBinomialCoefficientsLookupTable(b *testing.B) {
	for i := 0; i < b.N; i++ {
		initBinomialCoefficientsLookupTable()
	}
}

func BenchmarkGetCombinationID(b *testing.B) {
	for n := uint64(0); n < 70; n++ {
		for k := uint64(0); k <= n; k++ {
			b.Run(fmt.Sprintf("n:%d_k:%d", n, k), func(b *testing.B) {
				c := NewUniqueUnorderedCombination(k)
				maxValue := Value(n - 1)
				for i := 0; i < b.N; i++ {
					c.getCombinationID(maxValue)
				}
			})
		}
	}
}

func BenchmarkSetCombinationID(b *testing.B) {
	for n := uint64(0); n < 70; n++ {
		for k := uint64(0); k <= n; k++ {
			b.Run(fmt.Sprintf("n:%d_k:%d", n, k), func(b *testing.B) {
				c := NewUniqueUnorderedCombination(k)
				maxValue := Value(n - 1)
				amountOfCombinations := uint64(binomialCoefficient(int(n), int(k)))
				combinationID := amountOfCombinations / 3
				b.Run("smart", func(b *testing.B) {
					for i := 0; i < b.N; i++ {
						c.setCombinationID(maxValue, 1)
						c.setCombinationID(maxValue, combinationID)
					}
				})
			})
		}
	}
}
