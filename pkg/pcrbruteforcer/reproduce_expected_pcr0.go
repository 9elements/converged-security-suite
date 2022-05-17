package pcrbruteforcer

import (
	"bytes"
	"context"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"hash"
	"runtime"
	"sync"
	"sync/atomic"
	"time"

	"github.com/9elements/converged-security-suite/v2/pkg/bruteforcer"
	"github.com/9elements/converged-security-suite/v2/pkg/errors"
	"github.com/9elements/converged-security-suite/v2/pkg/pcr"
	"github.com/9elements/converged-security-suite/v2/pkg/registers"
	"github.com/linuxboot/contest/pkg/xcontext"
)

const (
	// the limit for the linear bruteforcer
	maxACMPolicyLinearDistance = 128

	// the limit for the combinatorial bruteforcer (expensive)
	maxACMPolicyCombinatorialDistance = 2

	// defines minimal "disabled measurements" combinations handled by one goroutine
	minCombinationsPerRoutine = 1

	// enableCombinatorialStrategy enables a strategy to brute-force ACM Policy
	// Status register by finding a combination of bits to flip. This was the
	// initial approach before the nature of the corruptions was investaged,
	// and it became clear that a more effective strategy is just linear
	// decrement.
	enableCombinatorialStrategy = false
)

// ReproduceExpectedPCR0 brute-forces measurements to achieve the expected PCR0
// SHA1 or SHA256 value.
//
// If succeeded to reproduce, then `isSuccess` is true.
//
// The updated ACM_POLICY_STATUS value is returned as `updatedACMPolicyStatus`.
//
// All the problems are returned through `returnErr`.
//
// Current algorithm already supports disabling measurements, may be in future
// we will return the rest amended measurements as well.
func ReproduceExpectedPCR0(
	ctx xcontext.Context,
	expectedPCR0 []byte,
	flow pcr.Flow,
	measurements pcr.Measurements,
	imageBytes []byte,
) (isSuccess bool, locality uint8, updatedACMPolicyStatus *registers.ACMPolicyStatus, returnErr error) {
	var realMeasurements pcr.Measurements
	for _, ms := range measurements {
		if ms.IsFake() {
			continue
		}
		realMeasurements = append(realMeasurements, ms)
	}

	handler, err := newReproduceExpectedPCR0Handler(
		expectedPCR0,
		flow,
		realMeasurements,
		imageBytes,
	)
	if err != nil {
		return false, 0, nil, fmt.Errorf("unable to initialize a handler: %w", err)
	}
	return handler.Execute(ctx)
}

type reproduceExpectedPCR0Handler struct {
	expectedPCR0              []byte
	flow                      pcr.Flow
	precalculatedMeasurements []*pcr.CachedMeasurement
	imageBytes                []byte
	hashFuncFactory           func() hash.Hash
}

func newReproduceExpectedPCR0Handler(
	expectedPCR0 []byte,
	flow pcr.Flow,
	measurements pcr.Measurements,
	imageBytes []byte,
) (*reproduceExpectedPCR0Handler, error) {
	var hashFuncFactory func() hash.Hash
	switch len(expectedPCR0) {
	case sha1.Size:
		hashFuncFactory = sha1.New
	case sha256.Size:
		hashFuncFactory = sha256.New
	default:
		return nil, fmt.Errorf("invalid len for expectedPCR0: %d", len(expectedPCR0))
	}

	precalculatedMeasurements, err := cacheMeasurements(measurements, imageBytes, hashFuncFactory)
	if err != nil {
		return nil, fmt.Errorf("invalid measurements: %w", err)
	}

	return &reproduceExpectedPCR0Handler{
		expectedPCR0:              expectedPCR0,
		flow:                      flow,
		precalculatedMeasurements: precalculatedMeasurements,
		imageBytes:                imageBytes,
		hashFuncFactory:           hashFuncFactory,
	}, nil
}

func (h *reproduceExpectedPCR0Handler) Execute(
	_ctx context.Context,
) (
	isSuccess bool,
	locality uint8,
	updatedACMPolicyStatus *registers.ACMPolicyStatus,
	returnErr error,
) {
	ctx, ok := _ctx.(xcontext.Context)
	if !ok {
		ctx = xcontext.Extend(_ctx)
	}
	// To speedup brute-force process we try the expected locality first,
	// and only after that we try second expected locality.

	defer ctx.Tracer().StartSpan("reproduceExpectedPCR0Handler").Finish()

	// The expected locality.
	isSuccess, locality, updatedACMPolicyStatus, returnErr = h.execute(ctx, []uint8{h.flow.TPMLocality()})
	if isSuccess {
		return
	}

	// The second expected locality (flipping 0 and 3).
	var restLocalities []uint8
	switch h.flow.TPMLocality() {
	case 0:
		restLocalities = []uint8{3}
	case 3:
		restLocalities = []uint8{0}
	default:
		// The expected locality is neither 0 nor 3? We are not aware of
		// such cases. Let's try all other localities then :)
		for tryLocality := uint8(0); tryLocality < 4; tryLocality++ {
			if tryLocality == h.flow.TPMLocality() {
				continue
			}
			restLocalities = append(restLocalities, tryLocality)
		}
	}

	return h.execute(ctx, restLocalities)
}

func (h *reproduceExpectedPCR0Handler) execute(
	ctx xcontext.Context,
	localities []uint8,
) (
	isSuccess bool,
	locality uint8,
	updatedACMPolicyStatus *registers.ACMPolicyStatus,
	returnErr error,
) {
	ctx, cancelFunc := xcontext.WithCancel(ctx)

	returnErr = fmt.Errorf("unable to reproduce the expected PCR0 value")

	var returnCount uint64
	var wg sync.WaitGroup
	defer wg.Wait()
	for _, tryLocality := range localities {
		wg.Add(1)
		go func(tryLocality uint8) {
			defer wg.Done()
			ctx.Logger().Debugf("reproduce pcr0 starting bruteforce... (locality: %v)", tryLocality)

			startTime := time.Now()
			foundAnswer, v, err := h.newJob(tryLocality).Execute(ctx)
			elapsed := time.Since(startTime)

			if !foundAnswer && err == nil {
				ctx.Logger().Debugf("reproduce pcr0 did not find an answer (locality: %v, elapsed: %v)", tryLocality, elapsed)
				return
			}
			ctx.Logger().Debugf("reproduce pcr0 got an answer (locality: %v, elapsed: %v)", tryLocality, elapsed)

			if c := atomic.AddUint64(&returnCount, 1); c != 1 {
				ctx.Logger().Errorf("received a final answer with different localities")
				return
			}

			ctx.Logger().Debugf("received an answer (locality:%d, expectedLocality:%d): %v %v", tryLocality, h.flow.TPMLocality(), foundAnswer, err)
			cancelFunc()

			if foundAnswer && tryLocality != h.flow.TPMLocality() {
				// Append current errors (even if there are none) with an additional one:
				err = (&errors.MultiError{}).Add(
					err,
					fmt.Errorf("locality mismatch, expected:%d, reproduced:%d", h.flow.TPMLocality(), tryLocality),
				).ReturnValue()
			}

			isSuccess = true
			locality = tryLocality
			updatedACMPolicyStatus = v
			returnErr = err
		}(tryLocality)
	}

	return
}

func (h *reproduceExpectedPCR0Handler) newJob(
	locality uint8,
) *reproduceExpectedPCR0Job {
	return &reproduceExpectedPCR0Job{
		imageBytes:        h.imageBytes,
		measurements:      h.precalculatedMeasurements,
		hashFuncFactory:   h.hashFuncFactory,
		expectedPCR0:      h.expectedPCR0,
		locality:          locality,
		registerHashCache: newRegisterHashCache(),
	}
}

type reproduceExpectedPCR0Job struct {
	// immutable fields:
	imageBytes        []byte
	measurements      []*pcr.CachedMeasurement
	hashFuncFactory   func() hash.Hash
	expectedPCR0      []byte
	locality          uint8
	registerHashCache *registerHashCache
}

func (j *reproduceExpectedPCR0Job) Execute(
	ctx xcontext.Context,
) (isSuccess bool, actualACMPolicyStatus *registers.ACMPolicyStatus, retErr error) {
	var mErr errors.MultiError
	defer func() {
		retErr = mErr.ReturnValue()
	}()

	concurrencyFactor := runtime.GOMAXPROCS(0)

	ctx, cancelFn := xcontext.WithCancel(ctx)

	for disabledMeasurements := 0; disabledMeasurements < len(j.measurements); disabledMeasurements++ {
		disabledMeasurementsIterator := bruteforcer.NewUniqueUnorderedCombinationIterator(uint64(disabledMeasurements), int64(len(j.measurements)))

		maxCombinationID := disabledMeasurementsIterator.AmountOfCombinations() - 1
		combinationsPerRoutine := (maxCombinationID + 1) / uint64(concurrencyFactor)
		if combinationsPerRoutine < minCombinationsPerRoutine {
			combinationsPerRoutine = minCombinationsPerRoutine
		}

		type iterationResult struct {
			isSuccess             bool
			actualACMPolicyStatus *registers.ACMPolicyStatus
			err                   error
		}

		resultCh := make(chan iterationResult, concurrencyFactor+1)
		var wg sync.WaitGroup
		for startCombinationID := uint64(0); startCombinationID <= maxCombinationID; startCombinationID += combinationsPerRoutine {
			wg.Add(1)
			go func(disabledMeasurementsIterator *bruteforcer.UniqueUnorderedCombinationIterator, startCombinationID uint64) {
				defer wg.Done()
				endCombinationID := startCombinationID + combinationsPerRoutine
				if endCombinationID > maxCombinationID {
					endCombinationID = maxCombinationID + 1
				}
				if startCombinationID != 0 {
					disabledMeasurementsIterator.SetCombinationID(startCombinationID)
				}

				for combinationID := startCombinationID; combinationID < endCombinationID; combinationID++ {
					if ctx.IsSignaledWith() {
						return
					}
					_isSuccess, _actualACMPolicyStatus, _err := j.tryDisabledMeasurementsCombination(ctx, disabledMeasurementsIterator.GetCombinationUnsafe(), j.hashFuncFactory)
					if _isSuccess || _err != nil {
						resultCh <- iterationResult{
							isSuccess:             _isSuccess,
							actualACMPolicyStatus: _actualACMPolicyStatus,
							err:                   _err,
						}
						cancelFn()
						return
					}
					if !disabledMeasurementsIterator.Next() {
						break
					}
				}
			}(disabledMeasurementsIterator.Copy(), startCombinationID)
		}
		wg.Wait()
		close(resultCh)

		for result := range resultCh {
			if result.isSuccess && !isSuccess {
				isSuccess = true
				actualACMPolicyStatus = result.actualACMPolicyStatus
			}
			if result.err != nil {
				_ = mErr.Add(result.err)
			}
		}
		if isSuccess || mErr.Count() != 0 {
			return
		}
	}

	return
}

func (j *reproduceExpectedPCR0Job) tryDisabledMeasurementsCombination(
	ctx xcontext.Context,
	disabledMeasurementsCombination bruteforcer.UniqueUnorderedCombination,
	hashFuncFactory func() hash.Hash,
) (bool, *registers.ACMPolicyStatus, error) {
	var enabledMeasurements []*pcr.CachedMeasurement
	for idx, m := range j.measurements {
		isDisabled := false
		// TODO: refactor this O(N^2); generate the picked measurements from the get go
		for _, disableIdx := range disabledMeasurementsCombination {
			if idx == int(disableIdx) {
				isDisabled = true
				break
			}
		}
		if isDisabled {
			continue
		}
		enabledMeasurements = append(enabledMeasurements, m)
	}

	isSuccess, actualACMPolicyStatus, err := j.measurementsVerify(j.expectedPCR0, enabledMeasurements, hashFuncFactory)
	if !isSuccess {
		return false, nil, err
	}

	mErr := (&errors.MultiError{}).Add(err)
	for _, disabledMeasurementIdx := range disabledMeasurementsCombination {
		var m pcr.MeasureEvent
		for idx := range j.measurements {
			if int(disabledMeasurementIdx) == idx {
				m = j.measurements[idx]
				break
			}
		}
		if m == nil {
			ctx.Errorf("unable to find a measurement with index: %d", disabledMeasurementIdx)
			continue
		}
		_ = mErr.Add(fmt.Errorf("measurement '%s' was disabled to reproduce the hash", m.GetID()))
	}
	return true, actualACMPolicyStatus, mErr.ReturnValue()
}

func (j *reproduceExpectedPCR0Job) measurementsVerify(
	expectedHashValue []byte,
	enabledMeasurements []*pcr.CachedMeasurement,
	hasherFactory func() hash.Hash,
) (bool, *registers.ACMPolicyStatus, error) {
	switch {
	case len(enabledMeasurements) > 0 && enabledMeasurements[0].ID == pcr.MeasurementIDPCR0DATA:
		isSuccess, actualACMPolicyStatus, err := j.measurementsVerifyWithBruteForceACMPolicyStatus(expectedHashValue, enabledMeasurements, hasherFactory)
		if isSuccess || err != nil {
			return isSuccess, actualACMPolicyStatus, err
		}

	default:
		// just check that the measurements lead to the expected pcr0 value
		ms := make([]pcr.MeasureEvent, 0, len(enabledMeasurements))
		for _, m := range enabledMeasurements {
			ms = append(ms, m)
		}
		pcr0HashValue, err := pcr.CalculatePCR(j.imageBytes, j.locality, ms, hasherFactory(), nil)
		if err != nil {
			return false, nil, fmt.Errorf("unable to calculate PCR0 value: %w", err)
		}
		if bytes.Equal(pcr0HashValue, expectedHashValue) {
			return true, nil, nil
		}
	}

	return false, nil, nil
}

func (j *reproduceExpectedPCR0Job) measurementsVerifyWithBruteForceACMPolicyStatus(
	expectedHashValue []byte,
	enabledMeasurements []*pcr.CachedMeasurement,
	hasherFactory func() hash.Hash,
) (bool, *registers.ACMPolicyStatus, error) {
	if len(enabledMeasurements) < 1 {
		return false, nil, fmt.Errorf("empty measurements slice, cannot compute PCR0")
	}

	if enabledMeasurements[0].ID != pcr.MeasurementIDPCR0DATA {
		return false, nil, fmt.Errorf("first measurement is not the ACM policy status register")
	}

	acmPolicyStatus := enabledMeasurements[0].Data[0].ForceData
	if len(acmPolicyStatus) != 8 {
		return false, nil, fmt.Errorf("ACM POLICY STATUS register is expected to be 64bits, but it is %d bits", len(acmPolicyStatus)*8)
	}

	// try these in series because each completely fills the cpu
	strategies := []bruteForceStrategy{
		newLinearSearch(maxACMPolicyLinearDistance, j.imageBytes, expectedHashValue, hasherFactory, j.registerHashCache),
	}

	if enableCombinatorialStrategy {
		strategies = append(strategies, newCombinatorialSearch(maxACMPolicyCombinatorialDistance, j.imageBytes, expectedHashValue, hasherFactory, j.registerHashCache))
	}

	for _, s := range strategies {
		reg, issue, err := s.Process(j.locality, enabledMeasurements)
		if err != nil {
			// TODO: this needs to get fixed; treating program errors and algo outcome issues the same way
			return false, nil, err
		}
		if reg != nil {
			return true, reg, issue
		}
	}

	return false, nil, nil
}

//-----------------------------------------------------------------------------
// ACM bruteforcing strategies
//-----------------------------------------------------------------------------

type hashFactory func() hash.Hash
type issue error

type bruteForceStrategy interface {
	Process(locality uint8, ms []*pcr.CachedMeasurement) (*registers.ACMPolicyStatus, issue, error)
}

func cacheMeasurements(ms pcr.Measurements, image []byte, hashFactory hashFactory) ([]*pcr.CachedMeasurement, error) {
	msCached := make([]*pcr.CachedMeasurement, 0, len(ms))
	for i := 0; i < len(ms); i++ {
		cached, err := ms[i].Cache(image, hashFactory())
		if err != nil {
			return nil, err
		}
		msCached = append(msCached, cached)
	}
	return msCached, nil
}

type linearSearch struct {
	limit             int
	image             []byte
	expected          []byte
	hashFactory       hashFactory
	registerHashCache *registerHashCache
}

func newLinearSearch(limit int, image []byte, expected []byte, hashFactory hashFactory, registerHashCache *registerHashCache) *linearSearch {
	return &linearSearch{limit, image, expected, hashFactory, registerHashCache}
}

func (ls *linearSearch) Process(locality uint8, ms []*pcr.CachedMeasurement) (*registers.ACMPolicyStatus, issue, error) {
	type bruteForceContext struct {
		Hash          hash.Hash
		MeasureEvents []pcr.MeasureEvent
		Buffer        []byte
	}

	init := func() (*bruteForceContext, error) {
		fastMS := prepareFastMeasurements(ms, ls.image, ls.registerHashCache)
		return &bruteForceContext{
			Hash:          ls.hashFactory(),
			MeasureEvents: fastMS,
			Buffer:        fastMS[0].(*pcr0DataFastMeasurement).Data[:len(ms[0].Data[0].ForceData)],
		}, nil
	}

	check := func(ctx *bruteForceContext) (bool, error) {
		// check if this series of measurements lead to the expected pcr0
		pcr0HashValue, err := pcr.CalculatePCR(
			ls.image, locality, ctx.MeasureEvents,
			ctx.Hash, nil,
		)
		if err != nil {
			return false, err
		}

		return bytes.Equal(pcr0HashValue, ls.expected), nil
	}
	start := ms[0].Data[0].ForceData

	concurrencyFactor := runtime.GOMAXPROCS(0)
	blockSize := ls.limit / concurrencyFactor
	if blockSize < 1 {
		blockSize = 1
	}

	var wg sync.WaitGroup
	resultChan := make(chan []byte)
	errChan := make(chan error)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	for i := 0; i < concurrencyFactor; i++ {
		blockStart := i * blockSize
		blockEnd := (i + 1) * blockSize
		if i == concurrencyFactor-1 {
			blockEnd = ls.limit
		}

		wg.Add(1)
		go func(blockStart, blockEnd int, resultChan chan<- []byte, errChan chan<- error) {
			defer wg.Done()

			sctx, err := init()
			if err != nil {
				select {
				case errChan <- err:
				case <-ctx.Done():
				}
				return
			}

			blockValue := binary.LittleEndian.Uint64(start) - uint64(blockStart)

			for bi := blockStart; bi < blockEnd; bi++ {
				select {
				case <-ctx.Done():
					return
				default:
				}

				// will possibly underflow, but that's ok
				binary.LittleEndian.PutUint64(sctx.Buffer, blockValue)
				blockValue--

				ok, err := check(sctx)
				if err != nil {
					select {
					case errChan <- err:
					case <-ctx.Done():
					}
					return
				}
				if ok {
					select {
					case resultChan <- sctx.Buffer:
					case <-ctx.Done():
					}
					return
				}
			}
		}(blockStart, blockEnd, resultChan, errChan)
	}

	// cancel if there are no answers
	go func() {
		wg.Wait()
		cancel()
	}()

	select {
	case <-ctx.Done():
		// no answers and no errors, wg was just done
		return nil, nil, nil

	case err := <-errChan:
		return nil, nil, err

	case result := <-resultChan:
		var issue issue
		if !bytes.Equal(start, result) {
			issue = fmt.Errorf("changed ACM_POLICY_STATUS from %X to %X", start, result)
		}

		correctACMReg := registers.ParseACMPolicyStatusRegister(binary.LittleEndian.Uint64(result))
		return &correctACMReg, issue, nil
	}
}

type combinatorialSearch struct {
	limit             int
	image             []byte
	expected          []byte
	hashFactory       hashFactory
	registerHashCache *registerHashCache
}

func newCombinatorialSearch(limit int, image []byte, expected []byte, hashFactory hashFactory, registerHashCache *registerHashCache) *combinatorialSearch {
	return &combinatorialSearch{limit, image, expected, hashFactory, registerHashCache}
}

type pcr0DataFastMeasurement struct {
	Data              []byte
	RegisterHashCache *registerHashCache
}

var _ pcr.MeasureEvent = &pcr0DataFastMeasurement{}

func (*pcr0DataFastMeasurement) GetID() pcr.MeasurementID {
	return pcr.MeasurementIDPCR0DATA
}
func (m *pcr0DataFastMeasurement) CompileMeasurableData(image []byte) []byte {
	return m.Data
}
func (m *pcr0DataFastMeasurement) Calculate(image []byte, hashFunc hash.Hash) ([]byte, error) {
	reg := binary.LittleEndian.Uint64(m.Data)
	cachedHash := m.RegisterHashCache.Get(reg)
	if cachedHash != nil {
		return cachedHash, nil
	}

	_, err := hashFunc.Write(m.Data)
	if err != nil {
		return nil, err
	}

	defer hashFunc.Reset()
	hashValue := hashFunc.Sum(nil)
	m.RegisterHashCache.Set(reg, hashValue)
	return hashValue, nil
}

func newPCR0DataFastMeasurement(origMeasurement *pcr.CachedMeasurement, image []byte, cache *registerHashCache) *pcr0DataFastMeasurement {
	data := origMeasurement.CompileMeasurableData(image)
	b := make([]byte, len(data))
	copy(b, data)
	return &pcr0DataFastMeasurement{
		Data:              b,
		RegisterHashCache: cache,
	}
}

func prepareFastMeasurements(ms []*pcr.CachedMeasurement, image []byte, cache *registerHashCache) []pcr.MeasureEvent {
	copyMS := make([]pcr.MeasureEvent, len(ms))
	for idx, m := range ms {
		if m.ID == pcr.MeasurementIDPCR0DATA {
			copyMS[idx] = newPCR0DataFastMeasurement(m, image, cache)
		} else {
			copyMS[idx] = m
		}
	}
	return copyMS
}

func (cs *combinatorialSearch) Process(locality uint8, ms []*pcr.CachedMeasurement) (*registers.ACMPolicyStatus, issue, error) {
	type bruteForceContext struct {
		Hash          hash.Hash
		MeasureEvents []pcr.MeasureEvent
	}

	initFunc := func() (interface{}, error) {
		return &bruteForceContext{
			Hash:          cs.hashFactory(),
			MeasureEvents: prepareFastMeasurements(ms, cs.image, cs.registerHashCache),
		}, nil
	}

	verifyFunc := func(_ctx interface{}, data []byte) bool {
		ctx := _ctx.(*bruteForceContext)
		copy(ctx.MeasureEvents[0].(*pcr0DataFastMeasurement).Data, data)

		// check if this series of measurements lead to the expected pcr0
		pcr0HashValue, err := pcr.CalculatePCR(
			cs.image, locality, ctx.MeasureEvents,
			ctx.Hash, nil,
		)
		if err != nil {
			// TODO: should prob return the error here instead of eating it
			return false
		}

		return bytes.Equal(pcr0HashValue, cs.expected)
	}
	start := ms[0].Data[0].ForceData

	combination, err := bruteforcer.BruteForceBytes(start, uint64(cs.limit), initFunc, verifyFunc, 0)
	if combination == nil || err != nil {
		return nil, nil, err
	}

	ACMRegValue := make([]byte, len(start))
	copy(ACMRegValue, start)

	var issue error
	if len(combination) != 0 {
		combination.ApplyBitFlips(ACMRegValue)
		issue = fmt.Errorf("changed ACM_POLICY_STATUS from %X to %X", start, ACMRegValue)
	}

	correctACMReg := registers.ParseACMPolicyStatusRegister(binary.LittleEndian.Uint64(ACMRegValue))
	return &correctACMReg, issue, nil
}
