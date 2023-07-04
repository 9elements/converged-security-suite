// This package needs deep redesigning: there are more and more ways to do
// brute-forcing, so these modules should be flattened out instead of going
// coupling every method among each other.

package pcrbruteforcer

import (
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"hash"
	"runtime"
	"sync"
	"sync/atomic"
	"time"

	"github.com/9elements/converged-security-suite/v2/pkg/bootflow/actions/tpmactions"
	"github.com/9elements/converged-security-suite/v2/pkg/bootflow/datasources"
	"github.com/9elements/converged-security-suite/v2/pkg/bootflow/steps/intelsteps"
	"github.com/9elements/converged-security-suite/v2/pkg/bootflow/subsystems/trustchains/tpm"
	"github.com/9elements/converged-security-suite/v2/pkg/bruteforcer"
	"github.com/9elements/converged-security-suite/v2/pkg/errors"
	"github.com/9elements/converged-security-suite/v2/pkg/registers"
	"github.com/facebookincubator/go-belt"
	"github.com/facebookincubator/go-belt/tool/experimental/errmon"
	"github.com/facebookincubator/go-belt/tool/logger"
)

const (
	// defines minimal "disabled measurements" combinations handled by one goroutine
	minCombinationsPerRoutine = 1
)

var (
	enabledSlowTracing = false
)

// ReproducePCR0Result represents the applied PCR bruteforce methods: check different localities, ACM_POLICY_STATUS, disabling measurements
type ReproducePCR0Result struct {
	Locality             uint8
	ACMPolicyStatus      *registers.ACMPolicyStatus
	DisabledMeasurements []*tpm.CommandLogEntry
	OrderSwaps           OrderSwaps
}

// SettingsBruteforceACMPolicyStatus defines settings of how to reproduce Intel ACM Policy Status.
type SettingsBruteforceACMPolicyStatus struct {
	// EnableACMPolicyCombinatorialStrategy enables a strategy to brute-force ACM Policy
	// Status register by finding a combination of bits to flip. This was the
	// initial approach before the nature of the corruptions was investigated,
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
	MaxReorders             int

	SettingsBruteforceACMPolicyStatus
}

// DefaultSettingsReproducePCR0 returns recommended default PCR0 settings
func DefaultSettingsReproducePCR0() SettingsReproducePCR0 {
	return SettingsReproducePCR0{
		MaxDisabledMeasurements:           4,
		MaxReorders:                       0,
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
	ctx context.Context,
	measurements tpm.CommandLog,
	hashAlgo tpm.Algorithm,
	expectedPCR0 tpm.Digest,
	settings SettingsReproducePCR0,
) (*ReproducePCR0Result, error) {
	logger.Debugf(ctx, "expectedPCR0 == %s", expectedPCR0)
	handler, err := newReproduceExpectedPCR0Handler(
		measurements,
		hashAlgo,
		expectedPCR0,
		settings,
	)
	if err != nil {
		return nil, fmt.Errorf("unable to initialize a handler: %w", err)
	}
	return handler.Execute(ctx)
}

type reproduceExpectedPCR0Handler struct {
	hashAlgo             tpm.Algorithm
	expectedPCR0         tpm.Digest
	filteredMeasurements []*tpm.CommandLogEntry
	settings             SettingsReproducePCR0
}

func newReproduceExpectedPCR0Handler(
	measurements tpm.CommandLog,
	hashAlgo tpm.Algorithm,
	expectedPCR0 tpm.Digest,
	settings SettingsReproducePCR0,
) (*reproduceExpectedPCR0Handler, error) {
	return &reproduceExpectedPCR0Handler{
		hashAlgo:             hashAlgo,
		expectedPCR0:         expectedPCR0,
		filteredMeasurements: filteredMeasurements(measurements, hashAlgo),
		settings:             settings,
	}, nil
}

func (h *reproduceExpectedPCR0Handler) Execute(ctx context.Context) (*ReproducePCR0Result, error) {
	// TODO: try first the locality we expect
	return h.execute(ctx, []uint8{0, 3})
}

func (h *reproduceExpectedPCR0Handler) execute(
	ctx context.Context,
	localities []uint8,
) (*ReproducePCR0Result, error) {
	ctx, cancelFunc := context.WithCancel(ctx)
	defer cancelFunc()

	var result *ReproducePCR0Result
	var returnCount uint64
	var wg sync.WaitGroup
	for _, tryLocality := range localities {
		wg.Add(1)
		go func(tryLocality uint8) {
			defer wg.Done()
			ctx := belt.WithField(ctx, "locality", tryLocality)
			defer func() {
				errmon.ObserveRecoverCtx(ctx, recover())
			}()

			logger.Debugf(ctx, "reproduce pcr0 starting bruteforce... (locality: %v)", tryLocality)

			startTime := time.Now()
			_result, err := h.newJob(tryLocality).Execute(ctx)
			elapsed := time.Since(startTime)

			if err != nil {
				logger.Errorf(ctx, "Failed to bruteforce for locality: '%d': '%v'", tryLocality, err)
				return
			}
			if _result == nil {
				logger.Debugf(ctx, "reproduce pcr0 did not find an answer (locality: %v, elapsed: %v)", tryLocality, elapsed)
				return
			}
			logger.Debugf(ctx, "reproduce pcr0 got an answer (locality: %v, elapsed: %v)", tryLocality, elapsed)

			if c := atomic.AddUint64(&returnCount, 1); c != 1 {
				logger.Errorf(ctx, "received the final answer using different localities")
				return
			}

			result = _result
			logger.Debugf(ctx, "received an answer (locality: %d): result:%v; err:%v", tryLocality, result, err)
			cancelFunc()

		}(tryLocality)
	}
	wg.Wait()
	return result, nil
}

func (h *reproduceExpectedPCR0Handler) newJob(
	locality uint8,
) *reproduceExpectedPCR0Job {
	return &reproduceExpectedPCR0Job{
		measurements:      h.filteredMeasurements,
		hashAlgo:          h.hashAlgo,
		expectedPCR0:      h.expectedPCR0,
		tpmInitCmd:        tpm.CommandInit{Locality: locality},
		settings:          h.settings,
		registerHashCache: newRegisterHashCache(),
		supportedAlgos:    []tpm.Algorithm{h.hashAlgo},
	}
}

type reproduceExpectedPCR0Job struct {
	// immutable fields:
	measurements      []*tpm.CommandLogEntry
	hashAlgo          tpm.Algorithm
	expectedPCR0      tpm.Digest
	tpmInitCmd        tpm.CommandInit
	settings          SettingsReproducePCR0
	registerHashCache *registerHashCache

	// cache:
	supportedAlgos []tpm.Algorithm
}

func isDone(ctx context.Context) bool {
	select {
	case <-ctx.Done():
		return true
	default:
		return false
	}
}

func (j *reproduceExpectedPCR0Job) Execute(
	ctx context.Context,
) (*ReproducePCR0Result, error) {
	concurrencyFactor := runtime.GOMAXPROCS(0)

	ctx, cancelFn := context.WithCancel(ctx)
	defer cancelFn()

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
			orderSwaps            OrderSwaps
			disabledMeasurements  []*tpm.CommandLogEntry
			actualACMPolicyStatus *registers.ACMPolicyStatus
			err                   error
		}

		resultCh := make(chan iterationResult, concurrencyFactor+1)
		var wg sync.WaitGroup
		for startCombinationID := uint64(0); startCombinationID <= maxCombinationID; startCombinationID += combinationsPerRoutine {
			wg.Add(1)
			go func(disabledMeasurementsIterator *bruteforcer.UniqueUnorderedCombinationIterator, startCombinationID uint64) {
				defer wg.Done()
				tpmInstance := tpm.NewTPM()
				buf := make([]bool, len(j.measurements))

				endCombinationID := startCombinationID + combinationsPerRoutine
				if endCombinationID > maxCombinationID {
					endCombinationID = maxCombinationID + 1
				}
				if startCombinationID != 0 {
					disabledMeasurementsIterator.SetCombinationID(startCombinationID)
				}

				for combinationID := startCombinationID; combinationID < endCombinationID; combinationID++ {
					if isDone(ctx) {
						return
					}
					disabledMeasurementsComb := disabledMeasurementsIterator.GetCombinationUnsafe()
					_isSuccess, _orderSwaps, _actualACMPolicyStatus, _err := j.tryDisabledMeasurementsCombination(ctx, tpmInstance, disabledMeasurementsComb, buf)
					if _isSuccess || _err != nil {
						var disabledMeasurements []*tpm.CommandLogEntry
						if _isSuccess {
							for _, disabledMeasurementIdx := range disabledMeasurementsComb {
								for idx := range j.measurements {
									if int(disabledMeasurementIdx) == idx {
										disabledMeasurements = append(disabledMeasurements, j.measurements[idx])
										break
									}
								}
							}
						}

						resultCh <- iterationResult{
							isSuccess:             _isSuccess,
							orderSwaps:            _orderSwaps,
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
			orderSwaps            OrderSwaps
			actualACMPolicyStatus *registers.ACMPolicyStatus
			disabledMeasurements  []*tpm.CommandLogEntry
			mErr                  errors.MultiError
		)
		for result := range resultCh {
			if result.isSuccess && !isSuccess {
				isSuccess = true
				orderSwaps = result.orderSwaps
				disabledMeasurements = result.disabledMeasurements
				actualACMPolicyStatus = result.actualACMPolicyStatus
			}
			if result.err != nil {
				_ = mErr.Add(result.err)
			}
		}

		if isSuccess {
			return &ReproducePCR0Result{
				Locality:             j.tpmInitCmd.Locality,
				ACMPolicyStatus:      actualACMPolicyStatus,
				DisabledMeasurements: disabledMeasurements,
				OrderSwaps:           orderSwaps,
			}, nil
		}

		if err := mErr.ReturnValue(); err != nil {
			return nil, err
		}
	}
	return nil, nil
}

func (j *reproduceExpectedPCR0Job) tryDisabledMeasurementsCombination(
	ctx context.Context,
	tpmInstance *tpm.TPM,
	disabledMeasurementsCombination bruteforcer.UniqueUnorderedCombination,
	buf []bool,
) (bool, OrderSwaps, *registers.ACMPolicyStatus, error) {
	var enabledMeasurements []*tpm.CommandLogEntry
	disabledCount := 0
	idxShifts := make([]int, 0, len(enabledMeasurements))
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
			disabledCount++
			continue
		}
		idxShifts = append(idxShifts, disabledCount)
		enabledMeasurements = append(enabledMeasurements, m)
	}

	success, orderSwaps, acmPSR, err := j.measurementsVerify(ctx, tpmInstance, j.expectedPCR0, enabledMeasurements, buf)

	// Inside measurementsVerify we worked with a subset of measurements which excludes
	// the disabled measurements. But these indexes are wrong in context of full set of
	// measurements, correcting the indexes:
	for idx := range orderSwaps {
		orderSwap := &orderSwaps[idx]
		orderSwap.IdxA += idxShifts[orderSwap.IdxA]
		orderSwap.IdxB += idxShifts[orderSwap.IdxB]
	}

	return success, orderSwaps, acmPSR, err
}

func (j *reproduceExpectedPCR0Job) measurementsVerify(
	ctx context.Context,
	tpmInstance *tpm.TPM,
	expectedHashValue tpm.Digest,
	enabledMeasurements []*tpm.CommandLogEntry,
	buf []bool,
) (bool, OrderSwaps, *registers.ACMPolicyStatus, error) {
	switch {
	case len(enabledMeasurements) > 0 && isMeasurePCR0DATACmdLogEntry(enabledMeasurements[0]):
		orderSwaps, acmPolicyStatus, err := j.measurementsVerifyWithBruteForceACMPolicyStatus(
			ctx,
			expectedHashValue,
			enabledMeasurements,
		)
		if err != nil {
			return false, nil, nil, err
		}
		if acmPolicyStatus == nil {
			return false, nil, nil, nil
		}
		return true, orderSwaps, acmPolicyStatus, nil

	default:
		if success, orderSwaps := j.bruteforceOrder(
			ctx,
			tpmInstance,
			expectedHashValue,
			enabledMeasurements,
			buf,
		); success {
			return success, orderSwaps, nil, nil
		}
	}
	return false, nil, nil, nil
}

type OrderSwap struct {
	IdxA int
	IdxB int
}

type OrderSwaps []OrderSwap

func ApplyOrderSwaps[T any](swaps OrderSwaps, s []T) {
	for _, swap := range swaps {
		s[swap.IdxA], s[swap.IdxB] = s[swap.IdxB], s[swap.IdxA]
	}
}

func (j *reproduceExpectedPCR0Job) bruteforceOrder(
	ctx context.Context,
	tpmInstance *tpm.TPM,
	expectedHashValue tpm.Digest,
	measurements []*tpm.CommandLogEntry,
	buf []bool,
) (bool, OrderSwaps) {
	if cap(buf) < len(measurements) {
		buf = make([]bool, len(measurements))
	} else {
		buf = buf[:len(measurements)]
		for idx := range buf {
			buf[idx] = false
		}
	}
	for swapsLimit := 0; swapsLimit <= j.settings.MaxReorders; swapsLimit++ {
		success, orderSwaps := (&orderBruteforcerJob{
			parent:            j,
			tpmInstance:       tpmInstance,
			expectedHashValue: expectedHashValue,
			measurements:      measurements,
			alreadySwapped:    buf,
			swapsLimit:        swapsLimit,
		}).executeRecursive(ctx)
		if success {
			return success, orderSwaps
		}
	}

	return false, nil
}

type orderBruteforcerJob struct {
	parent *reproduceExpectedPCR0Job

	tpmInstance         *tpm.TPM
	expectedHashValue   tpm.Digest
	measurements        []*tpm.CommandLogEntry
	alreadySwapped      []bool
	alreadySwappedCount int
	swapsLimit          int
}

func (j *orderBruteforcerJob) executeRecursive(
	ctx context.Context,
) (bool, OrderSwaps) {
	availableForOrderSwap := len(j.measurements) - j.alreadySwappedCount
	if j.swapsLimit == 0 || availableForOrderSwap < 2 {
		success := bytes.Equal(j.parent.replayTPMCommands(ctx, j.tpmInstance, j.measurements), j.expectedHashValue)
		return success, nil
	}

	iterator := bruteforcer.NewUniqueUnorderedCombinationIterator(
		2,
		int64(availableForOrderSwap-1),
	)
	j.alreadySwappedCount += 2
	j.swapsLimit--
	defer func() {
		j.alreadySwappedCount -= 2
		j.swapsLimit++
	}()

	for {
		combination := iterator.GetCombinationUnsafe()

		idxA, idxB := int(combination[0]), int(combination[1])
		//     v v v   v        -- the indexes over which the combination are bruteforced
		// 0 1 2 3 4 5 6        -- actual index values
		// S S n n n S n      S -- already swapped
		//     ^       ^      n -- not yet swapped
		//     0       3        -- the index values from within the combination area
		//     A       B        -- the name of the index
		//
		// shifts:
		// A += 2
		// B += 3
		for idx := range j.alreadySwapped {
			isSwapped := j.alreadySwapped[idx]
			if !isSwapped {
				continue
			}
			if idx <= idxA {
				idxA++
			}
			if idx <= idxB {
				idxB++
			}
		}

		j.alreadySwapped[idxA], j.alreadySwapped[idxB] = true, true
		j.measurements[idxA], j.measurements[idxB] = j.measurements[idxB], j.measurements[idxA]
		success, orderSwaps := j.executeRecursive(ctx)
		if success {
			return success, append(orderSwaps, OrderSwap{
				IdxA: idxA,
				IdxB: idxB,
			})
		}
		j.measurements[idxA], j.measurements[idxB] = j.measurements[idxB], j.measurements[idxA]
		j.alreadySwapped[idxA], j.alreadySwapped[idxB] = false, false
		if !iterator.Next() {
			break
		}
	}

	return false, nil
}

func isMeasurePCR0DATACmdLogEntry(logEntry *tpm.CommandLogEntry) bool {
	_, ok := logEntry.CauseCoordinates.Step().(intelsteps.MeasurePCR0DATA)
	return ok
}

func (j *reproduceExpectedPCR0Job) replayTPMCommands(
	ctx context.Context,
	tpmInstance *tpm.TPM,
	log []*tpm.CommandLogEntry,
) tpm.Digest {
	tpmInstance.DoNotUse_ResetNoInit()
	tpmInstance.SupportedAlgos = j.supportedAlgos
	err := j.tpmInitCmd.Apply(ctx, tpmInstance)
	if err != nil {
		// this is caught by recover()
		panic(err)
	}
	for _, cmd := range log {
		// call `apply` method because it is faster than `TPMExecute`.
		err := cmd.Command.Apply(ctx, tpmInstance)
		if err != nil {
			// this is caught by recover()
			panic(err)
		}
	}

	replayedPCR0 := tpmInstance.PCRValues[0][j.hashAlgo]
	if enabledSlowTracing {
		logger.Tracef(ctx, "replayedPCR == %s: %s %s", replayedPCR0, &j.tpmInitCmd, log)
	}
	return replayedPCR0
}

func (j *reproduceExpectedPCR0Job) measurementsVerifyWithBruteForceACMPolicyStatus(
	ctx context.Context,
	expectedHashValue tpm.Digest,
	enabledMeasurements []*tpm.CommandLogEntry,
) (OrderSwaps, *registers.ACMPolicyStatus, error) {
	if len(enabledMeasurements) < 1 {
		return nil, nil, fmt.Errorf("empty measurements slice, cannot compute PCR0")
	}

	_, ok := enabledMeasurements[0].CauseCoordinates.Step().(intelsteps.MeasurePCR0DATA)
	if !ok {
		return nil, nil, fmt.Errorf("the first TPM command is not caused by a MeasurePCR0DATA step")
	}

	// supposed to be always doable for a MeasurePCR0DATA step:
	action := enabledMeasurements[0].CauseAction.(*tpmactions.TPMExtend)
	dataSource := action.DataSource.(*datasources.StaticData)
	pcr0DataBytes := dataSource.RawBytes()
	acmPolicyStatusRef := dataSource.References[0]

	acmPolicyStatusOrig := acmPolicyStatusRef.RawBytes()
	if len(acmPolicyStatusOrig) != 8 {
		return nil, nil, fmt.Errorf("ACM POLICY STATUS register is expected to be 64bits, but it is %d bits", len(acmPolicyStatusOrig)*8)
	}

	type bruteForceContext struct {
		TPMInstance  *tpm.TPM
		Hasher       hash.Hash
		Measurements []*tpm.CommandLogEntry
		Buf          []bool

		PCR0DataDigestPointer tpm.Digest
	}

	h, err := j.hashAlgo.Hash()
	if err != nil {
		return nil, nil, fmt.Errorf("unable to initialize hasher factory for algorithm %s: %w", j.hashAlgo, err)
	}

	init := func() ([]byte, any, error) {
		acmPolicyStatusValue := make([]byte, len(acmPolicyStatusOrig))
		copy(acmPolicyStatusValue, acmPolicyStatusOrig)
		measurements := make([]*tpm.CommandLogEntry, len(enabledMeasurements))
		copy(measurements, enabledMeasurements)
		cmd := &tpm.CommandExtend{
			PCRIndex: 0,
			HashAlgo: j.hashAlgo,
			Digest:   make([]byte, h.Size()),
		}
		measurements[0] = &tpm.CommandLogEntry{
			Command:          cmd,
			CauseCoordinates: measurements[0].CauseCoordinates,
			CauseAction:      measurements[0].CauseAction,
		}

		return acmPolicyStatusValue,
			&bruteForceContext{
				TPMInstance:           tpm.NewTPM(),
				Hasher:                h.New(),
				Measurements:          measurements,
				Buf:                   make([]bool, len(measurements)),
				PCR0DataDigestPointer: cmd.Digest,
			}, nil
	}

	// TODO: fix consistency on control flow between orderSwapsResult and reg.
	var orderSwapsResult OrderSwaps
	orderSwapsSetCount := uint32(0)
	check := func(_ctx any, data []byte) (bool, error) {
		lctx := _ctx.(*bruteForceContext)
		// check if this series of measurements lead to the expected pcr0
		hasher := lctx.Hasher
		measurements := lctx.Measurements

		hasher.Reset()
		hasher.Write(data)
		hasher.Write(pcr0DataBytes[len(data):])
		hasher.Sum(lctx.PCR0DataDigestPointer[:0])

		success, orderSwaps := j.bruteforceOrder(ctx, lctx.TPMInstance, j.expectedPCR0, measurements, lctx.Buf)
		if success {
			switch atomic.AddUint32(&orderSwapsSetCount, 1) {
			case 1:
				orderSwapsResult = orderSwaps
			case 2:
				return success, fmt.Errorf("internal error: order swaps are already set")
			}
		}
		return success, nil
	}

	// try these in series because each completely fills the cpu
	strategies := []acmPolicyStatusBruteForceStrategy{
		newLinearSearch(j.settings.MaxACMPolicyLinearDistance, expectedHashValue),
	}

	if j.settings.EnableACMPolicyCombinatorialStrategy {
		strategies = append(strategies, newCombinatorialSearch(j.settings.MaxACMPolicyCombinatorialDistance, expectedHashValue))
	}

	for _, s := range strategies {
		reg, err := s.Process(init, check)
		if err != nil {
			return orderSwapsResult, nil, err
		}
		if reg != nil {
			return orderSwapsResult, reg, nil
		}
	}

	return orderSwapsResult, nil, nil
}

//-----------------------------------------------------------------------------
// ACM bruteforcing strategies
//-----------------------------------------------------------------------------

type acmPolicyStatusBruteForceStrategy interface {
	Process(
		init func() ([]byte, any, error),
		check func(ctx any, data []byte) (bool, error),
	) (*registers.ACMPolicyStatus, error)
}

func filteredMeasurements(ms tpm.CommandLog, hashAlgo tpm.Algorithm) []*tpm.CommandLogEntry {
	var result []*tpm.CommandLogEntry
	for idx, m := range ms {
		cmd, ok := m.Command.(*tpm.CommandExtend)
		if !ok {
			continue
		}
		if cmd.PCRIndex != 0 || cmd.HashAlgo != hashAlgo {
			continue
		}
		result = append(result, &ms[idx])
	}
	return result
}

type linearSearch struct {
	limit    int
	expected []byte
}

func newLinearSearch(limit int, expected []byte) *linearSearch {
	return &linearSearch{limit, expected}
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
	expected []byte
}

func newCombinatorialSearch(limit int, expected []byte) *combinatorialSearch {
	return &combinatorialSearch{limit, expected}
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

	combination, err := bruteforcer.BruteForce(startACMPolicyStatus, 8, 0, uint64(cs.limit), initFunc, verifyFunc, bruteforcer.ApplyBitFlipsBytes, 0)
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
