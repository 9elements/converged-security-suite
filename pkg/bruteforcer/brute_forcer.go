package bruteforcer

import (
	"fmt"
	"math"
	"math/big"
	"runtime"
	"sync"

	"github.com/9elements/converged-security-suite/v2/pkg/errors"
)

const (
	minIterationsPerCPU = 10000
)

type Item interface {
	any
}

type Slice[T Item] interface {
	~[]T
}

type ApplyBitFlipsFunc[E Item] func(combination UniqueUnorderedCombination, data []E)

// CheckFunc is the function used if the sought value is found. Return true
// if data is the sought value, and return false if it is not.
type CheckFunc[E Item] func(ctx any, data []E) bool

// InitFunc is the function executed for each goroutine before brute-forcing.
// It returns a data, which will be passed as argument `ctx` to CheckFunc.
type InitFunc func() (any, error)

type bruteForcer[E Item, T Slice[E]] struct {
	initialData       T
	initFunc          InitFunc
	checkFunc         CheckFunc[E]
	applyBitFlipsFunc ApplyBitFlipsFunc[E]
}

// BruteForce brute forces a value until checkFunc will return true or
// combinations will be out. It starts with value initialData and then
// tries combination with the hamming distance (relatively to initialDate) not
// greater than maxDistance.
//
// On success it returns the combination of bits which combination are required
// to be changed. To apply these changes use method ApplyBitFlips.
func BruteForce[E Item, T Slice[E]](
	initialData T,
	itemSize uint64,
	minDistance uint64,
	maxDistance uint64,
	initFunc InitFunc,
	checkFunc CheckFunc[E],
	applyBitFlipsFunc ApplyBitFlipsFunc[E],
	maxConcurrency uint,
) (UniqueUnorderedCombination, error) {
	return run(
		newBruteForcer(initialData, initFunc, checkFunc, applyBitFlipsFunc),
		itemSize,
		minDistance,
		maxDistance,
		maxConcurrency,
	)
}

func newBruteForcer[E Item, T Slice[E]](
	initialData T,
	initFunc InitFunc,
	checkFunc CheckFunc[E],
	applyBitFlipsFunc ApplyBitFlipsFunc[E],
) *bruteForcer[E, T] {
	if initFunc == nil {
		initFunc = func() (any, error) { return nil, nil }
	}
	return &bruteForcer[E, T]{
		initialData:       initialData,
		initFunc:          initFunc,
		checkFunc:         checkFunc,
		applyBitFlipsFunc: applyBitFlipsFunc,
	}
}

func run[E Item, T Slice[E]](
	b *bruteForcer[E, T],
	itemSize uint64,
	minDistance uint64,
	maxDistance uint64,
	maxConcurrency uint,
) (UniqueUnorderedCombination, error) {
	if minDistance > maxDistance {
		return nil, fmt.Errorf("minimal distance (%d) is higher than maximal distance (%d)", minDistance, maxDistance)
	}

	if minDistance == 0 {
		ctx, err := b.initFunc()
		if err != nil {
			return nil, err
		}

		if b.checkFunc(ctx, b.initialData) {
			return NewUniqueUnorderedCombination(0), nil
		}

		minDistance++
	}

	totalBitLength := uint64(len(b.initialData)) * itemSize
	if maxDistance > totalBitLength {
		maxDistance = totalBitLength
	}

	for distance := minDistance; distance <= maxDistance; distance++ {
		if totalBitLength < distance {
			// no combinations possible
			break
		}
		amountOfCombinationsBigInt := big.NewInt(1).Binomial(int64(totalBitLength), int64(distance))

		// Current algorithm uses an uint64 as an iterator through combinations,
		// thus we do not support more than math.MaxInt64 combinations.
		//
		// And amount of
		//
		// ">=" instead of ">" just for defense.
		if amountOfCombinationsBigInt.Cmp(big.NewInt(math.MaxInt64)) >= 0 {
			return nil, fmt.Errorf("distance is too high (amount of combinations causes uint64 overflow)")
		}
		amountOfCombinations := amountOfCombinationsBigInt.Uint64()

		// Calculating:
		// * concurrencyFactor -- how many concurrent goroutines are permitted.
		// * and combinationsPiece -- how many combinations should one goroutine handle.

		concurrencyFactor := runtime.GOMAXPROCS(0)
		if uint64(concurrencyFactor) > amountOfCombinations/minIterationsPerCPU {
			concurrencyFactor = int(amountOfCombinations / minIterationsPerCPU)
			if concurrencyFactor < 1 {
				concurrencyFactor = 1
			}
		}
		if maxConcurrency > 0 && uint(concurrencyFactor) > maxConcurrency {
			concurrencyFactor = int(maxConcurrency)
		}
		combinationsPiece := amountOfCombinations / uint64(concurrencyFactor)

		// Brute force!

		var locker sync.Mutex
		var resultData UniqueUnorderedCombination
		var wg sync.WaitGroup
		errChan := make(chan error, concurrencyFactor)

		for i := 0; i < concurrencyFactor; i++ {
			combinationIDStart := uint64(i) * combinationsPiece
			combinationIDEnd := uint64(i+1) * combinationsPiece
			if i == concurrencyFactor-1 {
				combinationIDEnd = amountOfCombinations
			}

			wg.Add(1)
			go func(combinationIDStart, combinationIDEnd uint64, errChan chan<- error) {
				defer wg.Done()
				dataCopy := make(T, len(b.initialData))
				copy(dataCopy, b.initialData)

				iterator := NewUniqueUnorderedCombinationIterator(distance, int64(totalBitLength)-1)
				iterator.SetCombinationID(combinationIDStart)

				bfctx, err := b.initFunc()
				if err != nil {
					errChan <- fmt.Errorf("brute forcer initFunc error for range (%v, %v): %v", combinationIDStart, combinationIDEnd, err)
					return
				}

				combinations := combinationIDEnd - combinationIDStart
				for i := uint64(0); ; {
					if resultData != nil {
						// we do not need atomic in the condition above, because
						// few false negatives will not affect anything much.
						return
					}

					if try(b, bfctx, dataCopy, iterator) {
						locker.Lock()
						resultData = iterator.GetCombination()
						locker.Unlock()
						return
					}
					i++
					if i >= combinations {
						break
					}
					iterator.Next()
				}
			}(combinationIDStart, combinationIDEnd, errChan)
		}

		// wait for all workers and gather errors
		wg.Wait()
		close(errChan)

		var errors errors.MultiError
		for err := range errChan {
			_ = errors.Add(err)
		}

		if len(errors) > 0 {
			return nil, fmt.Errorf("workers had errors: %v", errors)
		}

		if resultData != nil {
			return resultData, nil
		}
	}

	return nil, nil
}

func try[E Item, T Slice[E]](b *bruteForcer[E, T], ctx any, data T, iterator *UniqueUnorderedCombinationIterator) bool {
	// flipping the bits
	b.applyBitFlipsFunc(iterator.GetCombinationUnsafe(), data)

	// try
	if b.checkFunc(ctx, data) {
		return true
	}

	// wrong, flipping back the bits
	b.applyBitFlipsFunc(iterator.GetCombinationUnsafe(), data)
	return false
}
