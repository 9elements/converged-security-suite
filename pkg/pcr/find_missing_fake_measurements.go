package pcr

import (
	"bytes"
	"crypto/sha1"
	"hash"
	"runtime"
	"sync"
	"sync/atomic"

	pkgbytes "github.com/9elements/converged-security-suite/v2/pkg/bytes"
	"github.com/9elements/converged-security-suite/v2/pkg/uefi"
)

// findMissingFakeMeasurements is a slow bruteforcy procedure which will check
// if there's no byte in the firmware image which may affect PCR value
// calculation and is not covered by measurements.
//
// See also `pcr.SetFindMissingFakeMeasurements`.
func findMissingFakeMeasurements(
	firmware Firmware,
	pcrID ID,
	measurements Measurements,
	measureOpts ...MeasureOption,
) pkgbytes.Ranges {
	// Strategy:
	//
	// Trying to damage bytes one by one and check the results...
	// ... Whoops, wait... Since images takes few MiBs and fiano/firmware is
	// slow [1, 2], we cannot naively iterate over each byte (damage it)
	// and re-test the result. So we have to use bisection.
	//
	// So we create a queue and workers.
	//
	// [1] https://github.com/linuxboot/fiano/issues/310
	// [2] https://github.com/linuxboot/fiano/issues/304
	//
	// And since we use bisection, to do not over-complicate code
	// we will focus only on "no problems on damaged bytes
	// outside of measured ranges". So we will exclude the byte ranges
	// which are already covered by measurements.
	//
	// Also we need to keep in mind that this strategy is efficient
	// only while we have not very much of missed bytes which could
	// affect the PCR calculation. So we limit amount of iterations
	// by `queueLength` below.
	//
	// To do not pass a lot of data (some of them by pointers) to each worker
	// we create an intermediate struct "findMissingFakeMeasurementsJob".
	//
	// Terms:
	// * "Job" is an executed solver to get results for a problem.
	// * "Task" is a single check of one byte range.

	job := runFindMissingFakeMeasurementsJob(firmware, pcrID, measurements, measureOpts...)
	return job.Result()
}

type findMissingFakeMeasurementsJob struct {
	firmware         Firmware
	pcrID            ID
	measureOpts      []MeasureOption
	bytesLeft        int64
	measurementsOrig Measurements
	taskChan         chan findMissingFakeMeasurementsTask
	resultChan       chan pkgbytes.Range
	workersWG        sync.WaitGroup
	result           pkgbytes.Ranges
}

type findMissingFakeMeasurementsTask struct {
	Start uint64
	End   uint64
}

func (task *findMissingFakeMeasurementsTask) RangeLength() uint64 {
	return task.End - task.Start
}

func runFindMissingFakeMeasurementsJob(
	firmware Firmware,
	pcrID ID,
	measurements Measurements,
	measureOpts ...MeasureOption,
) *findMissingFakeMeasurementsJob {
	// Disabling option "FindMissingFakeMeasurements" to avoid
	// an infinite recursion:
	//    collectPCR0Measurements ->
	//    runFindMissingFakeMeasurementsJob ->
	//    GetPCRMeasurements ->
	//    collectPCR0Measurements ->
	//    ...
	//
	// TODO: Remove this hack. Design the API the way it won't require
	//       to modify options to avoid an infinite loop.
	var newMeasureOpts []MeasureOption
	for _, measureOpt := range measureOpts {
		if _, ok := measureOpt.(*SetFindMissingFakeMeasurements); ok {
			continue
		}
		newMeasureOpts = append(newMeasureOpts, measureOpt)
	}
	measureOpts = newMeasureOpts

	// Just an arbitrary value, feel free to change it
	// see `splitJob`.
	//
	// It defines how many tasks may fit into the task queue.
	// And if there is a big range with multiple differences
	// which would require to perform more tasks than
	// the queue can fit, then extra tasks will be immediately
	// added to the results (instead of splitting for more
	// accurate inspection).
	//
	// Basically, the higher this value is, the more accurate
	// result will be.
	queueLength := 100

	// Constructing the job:

	job := &findMissingFakeMeasurementsJob{
		firmware:         firmware,
		pcrID:            pcrID,
		measureOpts:      measureOpts,
		measurementsOrig: measurements,
		bytesLeft:        int64(len(firmware.Buf())),
		resultChan:       make(chan pkgbytes.Range, queueLength),
		taskChan:         make(chan findMissingFakeMeasurementsTask, queueLength),
	}
	initialTask := findMissingFakeMeasurementsTask{
		Start: 0,
		End:   uint64(job.bytesLeft),
	}

	// Running it:

	job.runWorkers()
	job.taskChan <- initialTask

	return job
}

func (job *findMissingFakeMeasurementsJob) runWorkers() {
	job.workersWG.Add(1)
	go func() {
		defer job.workersWG.Done()
		job.resultWorkerLoop()
	}()

	for i := 0; i < runtime.NumCPU()*2; i++ {
		job.workersWG.Add(1)
		go func() {
			defer job.workersWG.Done()
			job.taskWorkerLoop()
		}()
	}
}

func (job *findMissingFakeMeasurementsJob) resultWorkerLoop() {
	for {
		select {
		case r, ok := <-job.resultChan:
			if !ok {
				return
			}

			job.result = append(job.result, r)
		}
	}
}

func (job *findMissingFakeMeasurementsJob) taskWorkerLoop() {
	imageBytes := job.firmware.Buf()
	pcrHashFunc := sha1.New()

	damagedImagePreallocatedBuffer := make([]byte, len(imageBytes))

	measuredData := job.measurementsOrig.Data()
	var measuredRanges pkgbytes.Ranges
	for _, dataPiece := range measuredData {
		if dataPiece.Range.Length == 0 {
			continue
		}
		measuredRanges = append(measuredRanges, dataPiece.Range)
	}
	measuredRanges.SortAndMerge()
	pcr0Value := job.measurementsOrig.Calculate(job.firmware.Buf(), 0, pcrHashFunc, nil)

	for {
		select {
		case task, ok := <-job.taskChan:
			if !ok {
				return
			}
			job.processTask(imageBytes, measuredRanges, pcr0Value, pcrHashFunc, damagedImagePreallocatedBuffer, task)
		}
	}
}

// finishedTask is used when a range is not required to be analyzed
// anymore.
func (job *findMissingFakeMeasurementsJob) finishTask(
	task findMissingFakeMeasurementsTask,
) {
	// Reducing expected amount of data to be scanned:
	if atomic.AddInt64(&job.bytesLeft, -int64(task.RangeLength())) > 0 {
		// OK, still something left to be scanned, just return.
		return
	}

	// We already checked every single one byte, nothing is left to be scanned.

	// Closing the channel of incoming tasks:
	close(job.taskChan)

	// Also since there will be no new results, close the resultChan
	// as well:
	close(job.resultChan)
}

// splitTask is used when a problem was found in a byte range and
// it's required to split the task with a less ranges to get more
// details (more precise ranges).
func (job *findMissingFakeMeasurementsJob) splitTask(
	task findMissingFakeMeasurementsTask,
) {
	if len(job.taskChan)+1 >= cap(job.taskChan) {
		// See the description within findMissingFakeMeasurements
		// It seems there's too many "missed" areas which could affect
		// PCR0 calculation. And it will take too long to get precise
		// ranges of all of them (the queue of tasks is already overflowed).
		//
		// In other words, it's a range that produces differences out of
		// which lots of its binary splits also produce differences.
		//
		// So we just return this task as a resulting range
		// (without per-byte detalization). This is unprecise, but at
		// least doable in reasonable time.
		job.resultChan <- pkgbytes.Range{
			Offset: task.Start,
			Length: task.RangeLength(),
		}
		job.finishTask(task)
		return
	}

	middle := (task.Start + task.End) / 2
	job.taskChan <- findMissingFakeMeasurementsTask{
		Start: task.Start,
		End:   middle,
	}
	job.taskChan <- findMissingFakeMeasurementsTask{
		Start: middle,
		End:   task.End,
	}
}

func (job *findMissingFakeMeasurementsJob) processTask(
	imageBytes []byte,
	measuredRanges pkgbytes.Ranges,
	pcr0Value []byte,
	pcrHashFunc hash.Hash,
	damagedImageBytesBuf []byte,
	task findMissingFakeMeasurementsTask,
) {
	// See the description within findMissingFakeMeasurements

	copy(damagedImageBytesBuf, imageBytes)

	// damaging the bytes
	for damageIdx := task.Start; damageIdx < task.End; damageIdx++ {
		if measuredRanges.IsIn(damageIdx) {
			// See the description within findMissingFakeMeasurements,
			// we we try to damage bytes only outside of measured ranges.
			continue
		}

		// We require damagedImageBytesBuf[damageIdx] to be always changed here:
		// so the right part should always be in interval 1..255, so
		// we do (x % 255) + 1
		//
		// Also we require the right part be always the same for the same
		// damageIdx, since on next checks (when we will split the range) we
		// want to preserve the damage which makes PCR have different value,
		// so we may depend only on damageIdx.
		//
		// And the last: to shuffle possible damages better we multiply it
		// to a prime number (5867₁₀ == 1011011101011₂, and obviously 5867 is
		// larger than 255).
		damagedImageBytesBuf[damageIdx] ^= uint8(damageIdx*5867%255) + 1 // semi-random damage
	}

	// getting measurements from scratch

	firmwareDamaged, _ := uefi.ParseUEFIFirmwareBytes(damagedImageBytesBuf)

	var measurementsDamaged Measurements
	if firmwareDamaged != nil {
		measurementsDamaged, _, _, _ = GetMeasurements(firmwareDamaged, job.pcrID, job.measureOpts...)
	}

	// Checking the result.
	//
	// We expect no problem to be found.

	hasProblem := firmwareDamaged == nil || measurementsDamaged == nil
	if !hasProblem {
		pcr0ValueDamaged := measurementsDamaged.Calculate(firmwareDamaged.Buf(), 0, pcrHashFunc, nil)
		hasProblem = bytes.Compare(pcr0Value, pcr0ValueDamaged) != 0
	}

	if hasProblem {
		if task.End-task.Start > 1 {
			// We need to know specific bytes, so we split the range and try
			// again.
			job.splitTask(task)
			return
		}

		// OK, it seems we found a specific byte which may affect the
		// PCR calculation so we add it to the results.
		job.resultChan <- pkgbytes.Range{
			Offset: task.Start,
			Length: task.RangeLength(),
		}
	}

	// There was no problem, or it was an already an unsplittable range,
	// in both cases there's nothing to check in this range anymore.
	job.finishTask(task)
}

func (job *findMissingFakeMeasurementsJob) Wait() {
	job.workersWG.Wait()
}

func (job *findMissingFakeMeasurementsJob) Result() pkgbytes.Ranges {
	job.Wait()
	job.result.SortAndMerge()
	return job.result
}
