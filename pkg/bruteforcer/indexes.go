package bruteforcer

import (
	"fmt"
	"math"
	"math/big"
)

const (
	// We expect the bitsize of a bruteforced value be lower than 1000
	binomialCoefficientCacheMaxN = 1000

	// We expect distance be lower than 10
	binomialCoefficientCacheMaxK = 10
)

// Value is just an abstract index.
type Value int64

// UniqueUnorderedCombination is a combination of non-repeating
// unordered Value-s. To avoid combination duplication it is enforced
// that each next index should be greater than a previous one.
//
// See also: https://en.wikipedia.org/wiki/File:Combinations_without_repetition;_5_choose_3.svg
type UniqueUnorderedCombination []Value

// UniqueUnorderedCombinationIterator is a wrapper around
// UniqueUnorderedCombination which is able to set a next combination.
type UniqueUnorderedCombinationIterator struct {
	combination UniqueUnorderedCombination
	maxValue    Value
}

// NewUniqueUnorderedCombination returns a UniqueUnorderedCombination with combination
// pre-defined to [0, 1, 2, ...] -- the very first combination of unique
// (non-repeating) combination.
func NewUniqueUnorderedCombination(amountOfIndexes uint64) UniqueUnorderedCombination {
	s := make(UniqueUnorderedCombination, amountOfIndexes)
	for idx := range s {
		s[idx] = Value(idx)
	}
	return s
}

// ApplyBitFlipsBools changes bit combination located in combination UniqueUnorderedCombination
// of a []bool.
func ApplyBitFlipsBools(s UniqueUnorderedCombination, v []bool) {
	for _, idx := range s {
		v[idx] = !v[idx]
	}
}

// ApplyBitFlipsBytes changes bit combination located in combination UniqueUnorderedCombination
// of a []byte.
func ApplyBitFlipsBytes(s UniqueUnorderedCombination, v []byte) {
	for _, idx := range s {
		// major bits of "idx" are responsible for item index inside `b`
		byteIdx := idx >> 3 // idx / 8
		// minor bits of "idx" are responsible for bit-index inside `b[byteIndex]`
		bitIdx := idx & 0x7 // idx mod 8
		v[byteIdx] ^= 1 << bitIdx
	}
}

// next sets the next combination.
func (s UniqueUnorderedCombination) next(maxIndexValue Value) bool {
	if len(s) == 0 {
		return false
	}

	lastIdx := Value(len(s) - 1)
	idxIdx := lastIdx
	for ; idxIdx >= 0; idxIdx-- {
		s[idxIdx]++
		if s[idxIdx] <= maxIndexValue-(lastIdx-idxIdx) {
			break
		}
	}
	idxIdx++
	for ; idxIdx <= lastIdx; idxIdx++ {
		if idxIdx == 0 {
			return false
		}
		s[idxIdx] = s[idxIdx-1] + 1
	}

	return true
}

// AmountOfCombinations returns amount of possible combinations.
func (s UniqueUnorderedCombination) AmountOfCombinations(maxValue Value) uint64 {
	return binomialCoefficientFast(uint64(maxValue+1), uint64(len(s)))
}

func (s UniqueUnorderedCombination) setCombinationID(maxValue Value, combinationID uint64) {
	// To find the combination, first we try to iterate through the values
	// of the major index. Then we try to iterate through the values of the
	// next index. And so on until all indexes has correct values.
	//
	// Additional comment:
	//
	// We want to avoid stupid iterating through all combinations from
	// the beginning until required combinationID is reached. Therefore
	// we apply another algorithm. Relatively to axis of combinationID,
	// it is basically an N-section (like bisection, but not specifically "bi-")
	// search algorithm with unequal sections (if amount of indexes if at
	// least 2, then sum of all next sections is less or equals to than
	// the current section). Thus if amount of indexes is at least 2, then in
	// any case it gives O(ln(n)):
	// * If it is deep in left, then we will always increase depth, which
	//   gives O(ln(all_possible_combinations_amount))
	// * If it is deep in right, then we switch to next sections, which
	//   gives O(ln(all_possible_combinations_amount)), since every next
	//   section is at least twice smaller than the previous one.
	//
	// To understand more on how it works: read the big comment inside
	// function getCombinationID, first.

	setSeries := func(idx int, newValue Value) {
		l := len(s)
		for i := idx; i < l; i, newValue = i+1, newValue+1 {
			s[i] = newValue
		}
		if s[l-1] > maxValue {
			panic(fmt.Sprintf("internal error: should never happen: value %d is greater than maxValue %d", s[l-1], maxValue))
		}
	}

	// TODO: check maxValue and combinationID sanity.

	setSeries(0, 0)

	iteratorValueIndex := 0
	for {
		curID := s.getCombinationID(maxValue)
		if curID == combinationID {
			// Reached the required state.
			return
		}
		if curID > combinationID {
			// jumped over the required state, need to return and go deeper.
			setSeries(iteratorValueIndex, s[iteratorValueIndex]-1)
			iteratorValueIndex++
			continue
		}
		setSeries(iteratorValueIndex, s[iteratorValueIndex]+1)
	}
}

func (s UniqueUnorderedCombination) getCombinationID(maxValue Value) uint64 {
	// Let's imagine we have amountOfIndexes == 3, maxValue == 4, it gives us
	// these combinations:
	// 0 1 2
	// 0 1 3
	// 0 1 4
	// 0 2 3
	// 0 2 4
	// 0 3 4
	// 1 2 3
	// 1 2 4
	// 1 3 4
	// 2 3 4
	//
	// Here we have few combinations which has quite obvious IDs:
	// 0 1 2 -- has ID == 0
	// 1 2 3 -- has ID == C(5, 3) - C(4, 3)
	// 2 3 4 -- has ID == C(5, 3) - 1
	//
	// Where C(n, k) -- is a binomial coefficient.
	// For example let's explain why combination [1, 2, 3] has
	// ID == C(5, 3) - C(4, 3):
	// As an auxiliary step let's calculate these two values:
	// * The total amount of combinations is C(5, 3).
	// * The amount of combinations where the first value is
	//   greater or equals to "1" -- is C(4, 3), because it has 3 indexes
	//   and 4 possible values of an index.
	// Now since the ">=1"-valued combinations are in the tail, we can just
	// subtract C(4, 3) from C(5, 3) and receive the ID of the combination of
	// the very first combination with the first index equals to "1".
	//
	// In total specifically in this combinations-set we can say that combination
	// {x, x+1, x+2} has ID == C(5, 3) - C(5-x, 3)
	//
	//
	// Let's assume a generic rule:
	//
	// For amountOfIndexes = A, maxValue = M, a combination
	// x x+1 x+2 ... x+A-1 -- has ID = C(M+1, A) - C(M+1-x, A)
	//
	// And one may try to prove this method through mathematical induction or
	// through unit-tests (see brute_force_test.go)
	//
	// The problem is kind of solved. But span C(M, A) - C(M-1, A) is too
	// large (it is more than a half of all combinations) therefore we need
	// to split it as well.
	//
	// So let's take a look at cases of amountOfIndexes == 3, maxValue == 4
	// where index[0] == 0 and will try to construct a more
	// detailed formula for "ID":
	// 0 1 2
	// 0 1 3
	// 0 1 4
	// 0 2 3
	// 0 2 4
	// 0 3 4
	//
	// One might see it is an equivalent of amountOfIndexes == 2, maxValue == 3:
	//   0 1
	//   0 2
	//   0 3
	//   1 2
	//   1 3
	//   2 3
	// (just values are shifted by "-1" and the first index is removed)
	//
	// And we already know how to look for ID in here:
	// subID = C(3+1 - m, 2)
	//
	// Thus if amountOfIndexes = A, maxValue = M then combination:
	// n m m+1 m+2 ...
	// will have ID = ( C(M+1, A) - C(M+1-n, A) ) + ( C(M+1-n-1, A-1) - C(M+1-n-1-m, A-1) )
	//
	// Let's construct a generic function (which again could be proved either
	// through mathematical induction or through unit-tests):
	//
	// value_-1 = -1
	// ID_i = C(M+1 - value_(i-1) - 1, A-i) - C(M+1 - value_i, A-i)
	// ID = sum(i=0; i<A; i++) (ID_i)
	//
	// See unit-test: TestGetCombinationID

	var id uint64

	prevValue := uint64(math.MaxUint64) // effectively "-1"
	a := uint64(len(s))
	m := uint64(maxValue)
	for i := uint64(0); i < a; i++ {
		value := uint64(s[i])
		subID := binomialCoefficientFast(m+1-prevValue-1, a-i) - binomialCoefficientFast(m+1-value, a-i)
		id += subID
		prevValue = value
	}

	return id
}

var binomialCoefficientsLookupTable = [binomialCoefficientCacheMaxN + 1][binomialCoefficientCacheMaxK + 1]uint64{}

func binomialCoefficientFast(n, k uint64) uint64 {
	if n <= binomialCoefficientCacheMaxN && k <= binomialCoefficientCacheMaxK {
		return binomialCoefficientsLookupTable[n][k]
	}

	// TODO: implement a faster algorithm for this case:
	return big.NewInt(1).Binomial(int64(n), int64(k)).Uint64()
}

func initBinomialCoefficientsLookupTable() {
	for n := 0; n <= binomialCoefficientCacheMaxN; n++ {
		binomialCoefficientsLookupTable[n][0] = 1
	}
	for k := 1; k <= binomialCoefficientCacheMaxK; k++ {
		binomialCoefficientsLookupTable[0][k] = 0
	}

	for n := 1; n <= binomialCoefficientCacheMaxN; n++ {
		for k := 1; k <= binomialCoefficientCacheMaxK; k++ {
			// Pascal's rule:
			binomialCoefficientsLookupTable[n][k] = binomialCoefficientsLookupTable[n-1][k-1] + binomialCoefficientsLookupTable[n-1][k]
		}
	}

	// Is the code is unclear, then feel free to just google/duckduckgo:
	// "binomial coefficients dynamic programming".
}

func init() {
	initBinomialCoefficientsLookupTable()
}

func (s UniqueUnorderedCombination) Copy() UniqueUnorderedCombination {
	r := make(UniqueUnorderedCombination, len(s))
	copy(r, s)
	return r
}

// NewUniqueUnorderedCombinationIterator returns a new instance
// of UniqueUnorderedCombinationIterator.
func NewUniqueUnorderedCombinationIterator(amountOfValues uint64, maxValue int64) *UniqueUnorderedCombinationIterator {
	return &UniqueUnorderedCombinationIterator{
		combination: NewUniqueUnorderedCombination(amountOfValues),
		maxValue:    Value(maxValue),
	}
}

// Next sets the combination to the next combination.
func (iter *UniqueUnorderedCombinationIterator) Next() bool {
	return iter.combination.next(iter.maxValue)
}

// GetCombinationID returns current combination ID [0...amount_of_combinations)
func (iter *UniqueUnorderedCombinationIterator) GetCombinationID() uint64 {
	return iter.combination.getCombinationID(iter.maxValue)
}

// AmountOfCombinations returns amount of possible combinations.
func (iter *UniqueUnorderedCombinationIterator) AmountOfCombinations() uint64 {
	return iter.combination.AmountOfCombinations(iter.maxValue)
}

// SetCombinationID sets combination ID.
//
// The value should be within range [0...amount_of_combinations). Otherwise
// may hang or panic.
func (iter *UniqueUnorderedCombinationIterator) SetCombinationID(combinationID uint64) {
	iter.combination.setCombinationID(iter.maxValue, combinationID)
}

// GetCombination is a safe getter of the current combination.
//
// It performs a copy and therefore slow.
func (iter *UniqueUnorderedCombinationIterator) GetCombination() UniqueUnorderedCombination {
	// Go does not support read-only variables, therefore we copy:
	return iter.combination.Copy()
}

// GetCombinationUnsafe is an unsafe (but fast) getter of the current combination.
func (iter *UniqueUnorderedCombinationIterator) GetCombinationUnsafe() UniqueUnorderedCombination {
	return iter.combination
}

// Copy returns a deep copy of the iterator.
func (iter UniqueUnorderedCombinationIterator) Copy() *UniqueUnorderedCombinationIterator {
	iter.combination = iter.combination.Copy()
	return &iter
}
