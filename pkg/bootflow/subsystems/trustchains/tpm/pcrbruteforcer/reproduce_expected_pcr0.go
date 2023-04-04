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
	"github.com/9elements/converged-security-suite/v2/pkg/pcr"
	"github.com/9elements/converged-security-suite/v2/pkg/registers"
	"github.com/facebookincubator/go-belt/beltctx"
	"github.com/facebookincubator/go-belt/tool/experimental/errmon"
	"github.com/facebookincubator/go-belt/tool/logger"
)

const (
	// defines minimal "disabled measurements" combinations handled by one goroutine
	minCombinationsPerRoutine = 1
)

// ReproducePCR0Result represents the applied PCR bruteforce methods: check different localities, ACM_POLICY_STATUS, disabling measurements
type ReproducePCR0Result struct {
	Locality               uint8
	CorrectACMPolicyStatus *registers.ACMPolicyStatus
	DisabledMeasurements   tpm.CommandLog
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

	SettingsBruteforceACMPolicyStatus
}

// DefaultSettingsReproducePCR0 returns recommended default PCR0 settings
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
	ctx context.Context,
	measurements tpm.CommandLog,
	hashAlgo tpm.Algorithm,
	expectedPCR0 tpm.Digest,
	settings SettingsReproducePCR0,
) (*ReproducePCR0Result, error) {
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
	hashAlgo                  tpm.Algorithm
	expectedPCR0              tpm.Digest
	precalculatedMeasurements tpm.CommandLog
	settings                  SettingsReproducePCR0
}

func newReproduceExpectedPCR0Handler(
	measurements tpm.CommandLog,
	hashAlgo tpm.Algorithm,
	expectedPCR0 tpm.Digest,
	settings SettingsReproducePCR0,
) (*reproduceExpectedPCR0Handler, error) {
	return &reproduceExpectedPCR0Handler{
		hashAlgo:                  hashAlgo,
		expectedPCR0:              expectedPCR0,
		precalculatedMeasurements: preprocessMeasurements(measurements, hashAlgo),
		settings:                  settings,
	}, nil
}

func (h *reproduceExpectedPCR0Handler) Execute(ctx context.Context) (*ReproducePCR0Result, error) {
	// TODO: try first the locality we expect
	return h.execute(ctx, []uint8{0, 3})
}

func (h *reproduceExpectedPCR0Handler) execute(ctx context.Context, localities []uint8) (*ReproducePCR0Result, error) {
	ctx, cancelFunc := context.WithCancel(ctx)
	defer cancelFunc()

	var result *ReproducePCR0Result
	var returnCount uint64
	var wg sync.WaitGroup
	for _, tryLocality := range localities {
		wg.Add(1)
		go func(tryLocality uint8) {
			defer wg.Done()
			ctx = beltctx.WithField(ctx, "locality", tryLocality)
			defer func() {
				errmon.ObserveRecoverCtx(ctx, recover())
			}()

			logger.FromCtx(ctx).Debugf("reproduce pcr0 starting bruteforce... (locality: %v)", tryLocality)

			startTime := time.Now()
			_result, err := h.newJob(tryLocality).Execute(ctx)
			elapsed := time.Since(startTime)

			if _result == nil && err == nil {
				logger.FromCtx(ctx).Debugf("reproduce pcr0 did not find an answer (locality: %v, elapsed: %v)", tryLocality, elapsed)
				return
			}
			if err != nil {
				logger.FromCtx(ctx).Errorf("Failed to bruteforce for locality: '%d': '%v'", tryLocality, err)
				return
			}
			logger.FromCtx(ctx).Debugf("reproduce pcr0 got an answer (locality: %v, elapsed: %v)", tryLocality, elapsed)

			if c := atomic.AddUint64(&returnCount, 1); c != 1 {
				logger.FromCtx(ctx).Errorf("received a final answer with different localities")
				return
			}

			logger.FromCtx(ctx).Debugf("received an answer (locality: %d): %v %v", tryLocality, _result, err)
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
		measurements:      h.precalculatedMeasurements,
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
	measurements      tpm.CommandLog
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
			disabledMeasurements  tpm.CommandLog
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
					_isSuccess, _actualACMPolicyStatus, _err := j.tryDisabledMeasurementsCombination(ctx, tpmInstance, disabledMeasurementsComb)
					if _isSuccess || _err != nil {
						var disabledMeasurements tpm.CommandLog
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
			disabledMeasurements  tpm.CommandLog
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
				Locality:               j.tpmInitCmd.Locality,
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
	ctx context.Context,
	tpmInstance *tpm.TPM,
	disabledMeasurementsCombination bruteforcer.UniqueUnorderedCombination,
) (bool, *registers.ACMPolicyStatus, error) {
	var enabledMeasurements tpm.CommandLog
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

	return j.measurementsVerify(tpmInstance, j.expectedPCR0, enabledMeasurements)
}

func (j *reproduceExpectedPCR0Job) measurementsVerify(
	tpmInstance *tpm.TPM,
	expectedHashValue tpm.Digest,
	enabledMeasurements tpm.CommandLog,
) (bool, *registers.ACMPolicyStatus, error) {
	switch {
	case len(enabledMeasurements) > 0 && isMeasurePCR0DATACmdLogEntry(enabledMeasurements[0]):
		acmPolicyStatus, err := j.measurementsVerifyWithBruteForceACMPolicyStatus(expectedHashValue, enabledMeasurements)
		if err != nil {
			return false, nil, err
		}
		if acmPolicyStatus == nil {
			return false, nil, nil
		}
		return true, acmPolicyStatus, nil

	default:
		if bytes.Equal(j.replayTPMCommands(tpmInstance, enabledMeasurements), expectedHashValue) {
			return true, nil, nil
		}
	}
	return false, nil, nil
}

func isMeasurePCR0DATACmdLogEntry(logEntry tpm.CommandLogEntry) bool {
	_, ok := logEntry.CauseCoordinates.Flow[logEntry.CauseCoordinates.StepIndex].(intelsteps.MeasurePCR0DATA)
	return ok
}

func (j *reproduceExpectedPCR0Job) replayTPMCommands(
	tpmInstance *tpm.TPM,
	log tpm.CommandLog,
) tpm.Digest {
	tpmInstance.DoNotUse_ResetNoInit()
	tpmInstance.SupportedAlgos = j.supportedAlgos
	ctx := context.Background()
	err := tpmInstance.DoNotUse_TPMExecuteNoLog(ctx, &j.tpmInitCmd)
	if err != nil {
		// this is caught by recover()
		panic(err)
	}
	for _, cmd := range log {
		// call `apply` method because it is faster than `TPMExecute`.
		err := tpmInstance.DoNotUse_TPMExecuteNoLog(ctx, cmd)
		if err != nil {
			// this is caught by recover()
			panic(err)
		}
	}
	return tpmInstance.PCRValues[0][j.hashAlgo]
}

func (j *reproduceExpectedPCR0Job) measurementsVerifyWithBruteForceACMPolicyStatus(
	expectedHashValue tpm.Digest,
	enabledMeasurements tpm.CommandLog,
) (*registers.ACMPolicyStatus, error) {
	if len(enabledMeasurements) < 1 {
		return nil, fmt.Errorf("empty measurements slice, cannot compute PCR0")
	}

	_, ok := enabledMeasurements[0].CauseCoordinates.Step().(intelsteps.MeasurePCR0DATA)
	if !ok {
		return nil, fmt.Errorf("the first TPM command is not caused by a MeasurePCR0DATA step")
	}

	// supposed to be always doable for a MeasurePCR0DATA step:
	action := enabledMeasurements[0].CauseAction.(*tpmactions.TPMExtend)
	dataSource := action.DataSource.(*datasources.StaticData)
	pcr0DataBytes := dataSource.RawBytes()
	acmPolicyStatusRef := dataSource.References()[0]

	acmPolicyStatusOrig := acmPolicyStatusRef.RawBytes()
	if len(acmPolicyStatusOrig) != 8 {
		return nil, fmt.Errorf("ACM POLICY STATUS register is expected to be 64bits, but it is %d bits", len(acmPolicyStatusOrig)*8)
	}

	type bruteForceContext struct {
		TPMInstance  *tpm.TPM
		Hasher       hash.Hash
		Measurements tpm.CommandLog

		PCR0DataDigestPointer tpm.Digest
	}

	h, err := j.hashAlgo.Hash()
	if err != nil {
		return nil, fmt.Errorf("unable to initialize hasher factory for algorithm %s: %w", j.hashAlgo, err)
	}

	init := func() ([]byte, any, error) {
		acmPolicyStatusValue := make([]byte, len(acmPolicyStatusOrig))
		copy(acmPolicyStatusValue, acmPolicyStatusOrig)
		measurements := make(tpm.CommandLog, len(enabledMeasurements))
		copy(measurements, enabledMeasurements)
		cmd := &tpm.CommandExtend{
			PCRIndex: 0,
			HashAlgo: j.hashAlgo,
			Digest:   make([]byte, h.Size()),
		}
		measurements[0].Command = cmd

		return acmPolicyStatusValue,
			&bruteForceContext{
				TPMInstance:           tpm.NewTPM(),
				Hasher:                h.New(),
				Measurements:          measurements,
				PCR0DataDigestPointer: cmd.Digest,
			}, nil
	}

	check := func(_ctx any, data []byte) (bool, error) {
		ctx := _ctx.(*bruteForceContext)
		// check if this series of measurements lead to the expected pcr0
		hasher := ctx.Hasher
		measurements := ctx.Measurements

		hasher.Reset()
		hasher.Write(data)
		hasher.Write(pcr0DataBytes[len(data):])
		hasher.Sum(ctx.PCR0DataDigestPointer[:0])

		return bytes.Equal(j.replayTPMCommands(ctx.TPMInstance, measurements), j.expectedPCR0), nil
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

type acmPolicyStatusBruteForceStrategy interface {
	Process(
		init func() ([]byte, any, error),
		check func(ctx any, data []byte) (bool, error),
	) (*registers.ACMPolicyStatus, error)
}

func preprocessMeasurements(ms tpm.CommandLog, hashAlgo tpm.Algorithm) tpm.CommandLog {
	var result tpm.CommandLog
	for _, m := range ms {
		cmd, ok := m.Command.(*tpm.CommandExtend)
		if !ok {
			continue
		}
		if cmd.PCRIndex != 0 || cmd.HashAlgo != hashAlgo {
			continue
		}
		result = append(result, m)
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
