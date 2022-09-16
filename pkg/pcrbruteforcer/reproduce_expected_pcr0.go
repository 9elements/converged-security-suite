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
	// defines minimal "disabled measurements" combinations handled by one goroutine
	minCombinationsPerRoutine = 1
)

// ReproducePCR0Result represents the applied PCR bruteforce methods: check different localities, ACM_POLICY_STATUS, disabling measurements
type ReproducePCR0Result struct {
	Locality               uint8
	CorrectACMPolicyStatus *registers.ACMPolicyStatus
	DisabledMeasurements   pcr.Measurements
}

// SettingsBruteforceACMPolicyStatus defines settings of how to reproduce Intel ACM Policy Status.
type SettingsBruteforceACMPolicyStatus struct {
	// EnableACMPolicyCombinatorialStrategy enables a strategy to brute-force ACM Policy
	// Status register by finding a combination of bits to flip. This was the
	// initial approach before the nature of the corruptions was investaged,
	// and it became clear that a more effective strategy is just linear decrement.
	EnableACMPolicyCombinatorialStrategy bool

	// the limit for the combinatorial bruteforcer (expensive)
	MaxACMPolicyCombinatorialDistance int

	// MaxACMPolicyLinearDistance specifies a range of linear bruteforcer to try:
	// [initial value of ACM_POLICY_STATUS - MaxACMPolicyLinearDistance : initial value of ACM_POLICY_STATUS + MaxACMPolicyLinearDistance]
	MaxACMPolicyLinearDistance int
}

// DefaultSettingsBruteforceACMPolicyStatus returns recommended default settings to reproduce ACM Policy Status (given its digest and a close value).
func DefaultSettingsBruteforceACMPolicyStatus() SettingsBruteforceACMPolicyStatus {
	return SettingsBruteforceACMPolicyStatus{
		EnableACMPolicyCombinatorialStrategy: false,
		MaxACMPolicyCombinatorialDistance:    2,
		MaxACMPolicyLinearDistance:           128,
	}
}

// SettingsReproducePCR0 defines settings for internal bruteforce algorithms used in ReproduceExpectedPCR0
type SettingsReproducePCR0 struct {
	MaxDisabledMeasurements int

	SettingsBruteforceACMPolicyStatus
}

// DefaultSettingsReproducePCR0 returns recommeneded default PCR0 settings
func DefaultSettingsReproducePCR0() SettingsReproducePCR0 {
	return SettingsReproducePCR0{
		MaxDisabledMeasurements:           3,
		SettingsBruteforceACMPolicyStatus: DefaultSettingsBruteforceACMPolicyStatus(),
	}
}

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
	settings SettingsReproducePCR0,
) (*ReproducePCR0Result, error) {
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
		settings,
	)
	if err != nil {
		return nil, fmt.Errorf("unable to initialize a handler: %w", err)
	}
	return handler.Execute(ctx)
}

type reproduceExpectedPCR0Handler struct {
	expectedPCR0              []byte
	flow                      pcr.Flow
	precalculatedMeasurements []*pcr.CachedMeasurement
	imageBytes                []byte
	hashFuncFactory           func() hash.Hash
	settings                  SettingsReproducePCR0
}

func newReproduceExpectedPCR0Handler(
	expectedPCR0 []byte,
	flow pcr.Flow,
	measurements pcr.Measurements,
	imageBytes []byte,
	settings SettingsReproducePCR0,
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
		settings:                  settings,
	}, nil
}

func (h *reproduceExpectedPCR0Handler) Execute(ctx xcontext.Context) (*ReproducePCR0Result, error) {
	// To speedup brute-force process we try the expected locality first,
	// and only after that we try second expected locality.

	defer ctx.Tracer().StartSpan("reproduceExpectedPCR0Handler").Finish()

	// The expected locality.
	result, err := h.execute(ctx, []uint8{h.flow.TPMLocality()})
	if err != nil {
		return nil, err
	}
	if result != nil {
		return result, nil
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

func (h *reproduceExpectedPCR0Handler) execute(ctx xcontext.Context, localities []uint8) (*ReproducePCR0Result, error) {
	ctx, cancelFunc := xcontext.WithCancel(ctx)

	var result *ReproducePCR0Result
	var returnCount uint64
	var wg sync.WaitGroup
	for _, tryLocality := range localities {
		wg.Add(1)
		go func(tryLocality uint8) {
			defer wg.Done()
			ctx.Logger().Debugf("reproduce pcr0 starting bruteforce... (locality: %v)", tryLocality)

			startTime := time.Now()
			_result, err := h.newJob(tryLocality).Execute(ctx)
			elapsed := time.Since(startTime)

			if _result == nil && err == nil {
				ctx.Logger().Debugf("reproduce pcr0 did not find an answer (locality: %v, elapsed: %v)", tryLocality, elapsed)
				return
			}
			if err != nil {
				ctx.Errorf("Failed to bruteforce for locality: '%d': '%v'", tryLocality, err)
				return
			}
			ctx.Logger().Debugf("reproduce pcr0 got an answer (locality: %v, elapsed: %v)", tryLocality, elapsed)

			if c := atomic.AddUint64(&returnCount, 1); c != 1 {
				ctx.Logger().Errorf("received a final answer with different localities")
				return
			}

			ctx.Logger().Debugf("received an answer (locality:%d, expectedLocality:%d): %v %v", tryLocality, h.flow.TPMLocality(), _result, err)
			cancelFunc()

			result = _result
		}(tryLocality)
	}
	wg.Wait()
	return result, nil
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
		settings:          h.settings,
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
	settings          SettingsReproducePCR0
	registerHashCache *registerHashCache
}

func (j *reproduceExpectedPCR0Job) Execute(
	ctx xcontext.Context,
) (*ReproducePCR0Result, error) {
	concurrencyFactor := runtime.GOMAXPROCS(0)

	ctx, cancelFn := xcontext.WithCancel(ctx)

	maxDisabledMeasurements := len(j.measurements)
	if j.settings.MaxDisabledMeasurements < maxDisabledMeasurements {
		maxDisabledMeasurements = j.settings.MaxDisabledMeasurements
	}

	for disabledMeasurements := 0; disabledMeasurements < maxDisabledMeasurements; disabledMeasurements++ {
		disabledMeasurementsIterator := bruteforcer.NewUniqueUnorderedCombinationIterator(uint64(disabledMeasurements), int64(len(j.measurements)))

		maxCombinationID := disabledMeasurementsIterator.AmountOfCombinations() - 1
		combinationsPerRoutine := (maxCombinationID + 1) / uint64(concurrencyFactor)
		if combinationsPerRoutine < minCombinationsPerRoutine {
			combinationsPerRoutine = minCombinationsPerRoutine
		}

		type iterationResult struct {
			isSuccess             bool
			disabledMeasurements  pcr.Measurements
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
					disabledMeasurementsComb := disabledMeasurementsIterator.GetCombinationUnsafe()
					_isSuccess, _actualACMPolicyStatus, _err := j.tryDisabledMeasurementsCombination(ctx, disabledMeasurementsComb, j.hashFuncFactory)
					if _isSuccess || _err != nil {
						var disabledMeasurements pcr.Measurements
						if _isSuccess {
							for _, disabledMeasurementIdx := range disabledMeasurementsComb {
								for idx := range j.measurements {
									if int(disabledMeasurementIdx) == idx {
										disabledMeasurements = append(disabledMeasurements, &j.measurements[idx].Measurement)
										break
									}
								}
							}
						}

						resultCh <- iterationResult{
							isSuccess:             _isSuccess,
							disabledMeasurements:  disabledMeasurements,
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

		var (
			isSuccess             bool
			actualACMPolicyStatus *registers.ACMPolicyStatus
			disabledMeasurements  pcr.Measurements
			mErr                  errors.MultiError
		)
		for result := range resultCh {
			if result.isSuccess && !isSuccess {
				isSuccess = true
				disabledMeasurements = result.disabledMeasurements
				actualACMPolicyStatus = result.actualACMPolicyStatus
			}
			if result.err != nil {
				_ = mErr.Add(result.err)
			}
		}

		if isSuccess {
			return &ReproducePCR0Result{
				Locality:               j.locality,
				CorrectACMPolicyStatus: actualACMPolicyStatus,
				DisabledMeasurements:   disabledMeasurements,
			}, nil
		}

		if err := mErr.ReturnValue(); err != nil {
			return nil, err
		}
	}
	return nil, nil
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

	return j.measurementsVerify(j.expectedPCR0, enabledMeasurements, hashFuncFactory)
}

func (j *reproduceExpectedPCR0Job) measurementsVerify(
	expectedHashValue []byte,
	enabledMeasurements []*pcr.CachedMeasurement,
	hasherFactory func() hash.Hash,
) (bool, *registers.ACMPolicyStatus, error) {
	switch {
	case len(enabledMeasurements) > 0 && enabledMeasurements[0].ID == pcr.MeasurementIDPCR0DATA:
		acmPolicyStatus, err := j.measurementsVerifyWithBruteForceACMPolicyStatus(expectedHashValue, enabledMeasurements, hasherFactory)
		if err != nil {
			return false, nil, err
		}
		if acmPolicyStatus == nil {
			return false, nil, nil
		}
		return true, acmPolicyStatus, nil

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
) (*registers.ACMPolicyStatus, error) {
	if len(enabledMeasurements) < 1 {
		return nil, fmt.Errorf("empty measurements slice, cannot compute PCR0")
	}

	if enabledMeasurements[0].ID != pcr.MeasurementIDPCR0DATA {
		return nil, fmt.Errorf("first measurement is not the ACM policy status register")
	}

	acmPolicyStatus := enabledMeasurements[0].Data[0].ForceData
	if len(acmPolicyStatus) != 8 {
		return nil, fmt.Errorf("ACM POLICY STATUS register is expected to be 64bits, but it is %d bits", len(acmPolicyStatus)*8)
	}

	type bruteForceContext struct {
		Hash          hash.Hash
		MeasureEvents []pcr.MeasureEvent
	}

	init := func() ([]byte, any, error) {
		fastMS := prepareFastMeasurements(enabledMeasurements, j.imageBytes, j.registerHashCache)
		acmPolicyStatusValue := fastMS[0].(*pcr0DataFastMeasurement).Data[:len(enabledMeasurements[0].Data[0].ForceData)]
		return acmPolicyStatusValue,
			&bruteForceContext{
				Hash:          j.hashFuncFactory(),
				MeasureEvents: fastMS,
			}, nil
	}

	check := func(_ctx any, date []byte) (bool, error) {
		ctx := _ctx.(*bruteForceContext)
		// check if this series of measurements lead to the expected pcr0
		pcr0HashValue, err := pcr.CalculatePCR(
			j.imageBytes, j.locality, ctx.MeasureEvents,
			ctx.Hash, nil,
		)
		if err != nil {
			return false, err
		}

		return bytes.Equal(pcr0HashValue, j.expectedPCR0), nil
	}

	// try these in series because each completely fills the cpu
	strategies := []acmPolicyStatusBruteForceStrategy{
		newLinearSearch(j.settings.MaxACMPolicyLinearDistance, j.imageBytes, expectedHashValue),
	}

	if j.settings.EnableACMPolicyCombinatorialStrategy {
		strategies = append(strategies, newCombinatorialSearch(j.settings.MaxACMPolicyCombinatorialDistance, j.imageBytes, expectedHashValue))
	}

	for _, s := range strategies {
		reg, err := s.Process(init, check)
		if err != nil {
			return nil, err
		}
		if reg != nil {
			return reg, nil
		}
	}

	return nil, nil
}

//-----------------------------------------------------------------------------
// ACM bruteforcing strategies
//-----------------------------------------------------------------------------

type hashFactory func() hash.Hash

type acmPolicyStatusBruteForceStrategy interface {
	Process(
		init func() ([]byte, any, error),
		check func(ctx any, data []byte) (bool, error),
	) (*registers.ACMPolicyStatus, error)
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
	limit    int
	image    []byte
	expected []byte
}

func newLinearSearch(limit int, image []byte, expected []byte) *linearSearch {
	return &linearSearch{limit, image, expected}
}

// locality uint8, ms []*pcr.CachedMeasurement
func (ls *linearSearch) Process(
	init func() ([]byte, any, error),
	check func(ctx any, data []byte) (bool, error),
) (*registers.ACMPolicyStatus, error) {
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

			value, sctx, err := init()
			if err != nil {
				select {
				case errChan <- err:
				case <-ctx.Done():
				}
				return
			}

			blockValue := binary.LittleEndian.Uint64(value) - uint64(blockStart)

			for bi := blockStart; bi < blockEnd; bi++ {
				select {
				case <-ctx.Done():
					return
				default:
				}

				// will possibly underflow, but that's ok
				binary.LittleEndian.PutUint64(value, blockValue)
				blockValue--

				ok, err := check(sctx, value)
				if err != nil {
					select {
					case errChan <- err:
					case <-ctx.Done():
					}
					return
				}
				if ok {
					select {
					case resultChan <- value:
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
		return nil, nil

	case err := <-errChan:
		return nil, err

	case result := <-resultChan:
		correctACMReg := registers.ParseACMPolicyStatusRegister(binary.LittleEndian.Uint64(result))
		return &correctACMReg, nil
	}
}

type combinatorialSearch struct {
	limit    int
	image    []byte
	expected []byte
}

func newCombinatorialSearch(limit int, image []byte, expected []byte) *combinatorialSearch {
	return &combinatorialSearch{limit, image, expected}
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

func (cs *combinatorialSearch) Process(
	init func() ([]byte, any, error),
	check func(ctx any, data []byte) (bool, error),
) (*registers.ACMPolicyStatus, error) {
	type bruteForceContext struct {
		BackendContext any
		PCR0DATA       []byte
	}

	startPCR0DATA, _, _ := init()
	startACMPolicyStatus := startPCR0DATA[:8] // 8 is the size of registers.ACMPolicyStatus

	initFunc := func() (any, error) {
		buf, ctx, err := init()
		return &bruteForceContext{
			BackendContext: ctx,
			PCR0DATA:       buf,
		}, err
	}

	verifyFunc := func(_ctx any, acmPolicyStatus []byte) bool {
		ctx := _ctx.(*bruteForceContext)
		// overwriting the beginning of PCR0_DATA with new value of ACM Policy Status.
		copy(ctx.PCR0DATA, acmPolicyStatus)
		matched, err := check(ctx.BackendContext, ctx.PCR0DATA)
		if err != nil {
			// TODO: process error
			return false
		}
		return matched
	}

	combination, err := bruteforcer.BruteForce(startACMPolicyStatus, 8, uint64(cs.limit), initFunc, verifyFunc, bruteforcer.ApplyBitFlipsBytes, 0)
	if combination == nil || err != nil {
		return nil, err
	}

	acmPolicyStatus := make([]byte, len(startACMPolicyStatus))
	copy(acmPolicyStatus, startACMPolicyStatus)

	if len(combination) != 0 {
		bruteforcer.ApplyBitFlipsBytes(combination, acmPolicyStatus)
	}

	correctACMReg := registers.ParseACMPolicyStatusRegister(binary.LittleEndian.Uint64(acmPolicyStatus))
	return &correctACMReg, nil
}
