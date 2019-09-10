package test

import (
	"fmt"

	"github.com/9elements/txt-suite/pkg/api"
)

var (
	testtxtmemoryrangevalid = Test{
		Name:     "TXT memory ranges valid",
		Required: true,
		function: TestTXTRegisterSpaceValid,
		Status:   TestImplemented,
	}
	testmemoryisreserved = Test{
		Name:         "TXT memory reserved in e820",
		Required:     true,
		function:     TestTXTReservedInE820,
		dependencies: []*Test{&testtxtmemoryrangevalid},
		Status:       TestImplemented,
	}
	testtxtmemoryisdpr = Test{
		Name:         "TXT memory in a DMA protected range",
		Required:     true,
		function:     TestTXTMemoryIsDPR,
		dependencies: []*Test{&testtxtmemoryrangevalid},
		Status:       TestImplemented,
	}
	testtxtdprislocked = Test{
		Name:     "TXT DPR register locked",
		Required: true,
		function: TestTXTDPRisLock,
		Status:   TestImplemented,
	}
	testhostbridgeDPRcorrect = Test{
		Name:     "CPU DPR equals hostbridge DPR",
		Required: false,
		function: TestHostbridgeDPRCorrect,
		Status:   TestImplemented,
	}
	testhostbridgeDPRislocked = Test{
		Name:         "CPU hostbridge DPR register locked",
		Required:     true,
		function:     TestHostbridgeDPRisLocked,
		dependencies: []*Test{&testhostbridgeDPRcorrect},
		Status:       TestImplemented,
	}
	testsinitintxt = Test{
		Name:     "TXT region contains SINIT ACM",
		Required: true,
		function: TestSINITInTXT,
		Status:   TestImplemented,
	}
	testsinitmatcheschipset = Test{
		Name:         "SINIT ACM matches chipset",
		Required:     true,
		function:     TestSINITMatchesChipset,
		dependencies: []*Test{&testsinitintxt},
		Status:       TestImplemented,
	}
	testsinitmatchescpu = Test{
		Name:         "SINIT ACM matches CPU",
		Required:     true,
		function:     TestSINITMatchesCPU,
		dependencies: []*Test{&testsinitintxt},
		Status:       TestImplemented,
	}
	testnosiniterrors = Test{
		Name:     "SINIT ACM startup successful",
		Required: false,
		function: TestNoSINITErrors,
		Status:   TestImplemented,
	}
	testbiosdataregionpresent = Test{
		Name:     "BIOS DATA REGION present",
		Required: true,
		function: TestBIOSDATAREGIONPresent,
		Status:   TestImplemented,
	}
	testbiosdataregionvalid = Test{
		Name:         "BIOS DATA REGION valid",
		Required:     true,
		function:     TestBIOSDATAREGIONValid,
		dependencies: []*Test{&testbiosdataregionpresent},
		Status:       TestImplemented,
	}
	testbiosdatanumlogprocsvalid = Test{
		Name:         "BIOS DATA NumLogProcs valid",
		Required:     false,
		function:     TestBIOSDATANumLogProcsValid,
		dependencies: []*Test{&testbiosdataregionpresent},
		Status:       TestImplemented,
	}
	testhasmtrr = Test{
		Name:     "CPU supports MTRRs",
		Required: true,
		function: TestHasMTRR,
		Status:   TestImplemented,
	}
	testhassmrr = Test{
		Name:         "CPU supports SMRRs",
		Required:     true,
		function:     TestHasSMRR,
		dependencies: []*Test{&testservermodetext},
		Status:       TestImplemented,
	}
	testvalidsmrr = Test{
		Name:         "SMRR covers SMM memory",
		Required:     true,
		function:     TestValidSMRR,
		dependencies: []*Test{&testhassmrr},
		Status:       TestImplemented,
	}
	testactivesmrr = Test{
		Name:         "SMRR protection active",
		Required:     true,
		function:     TestActiveSMRR,
		dependencies: []*Test{&testhassmrr},
		Status:       TestImplemented,
	}
	testactiveiommi = Test{
		Name:     "IOMMU/VT-d active",
		Required: false,
		function: TestActiveIOMMU,
		Status:   TestImplemented,
	}
	testactivetboot = Test{
		Name:     "TBOOT hypervisor active",
		Required: false,
		function: TestActiveTBOOT,
		Status:   TestNotImplemented,
	}
	testservermodetext = Test{
		Name:     "TXT server mode enabled",
		Required: false,
		function: TestServerModeTXT,
		Status:   TestImplemented,
	}
	testreleasefusedfsbi = Test{
		Name:     "FSB interface release fused",
		Required: false,
		function: TestReleaseFusedFSBI,
		Status:   TestNotImplemented,
	}

	TestsMemory = [...]*Test{
		&testtxtmemoryrangevalid,
		&testmemoryisreserved,
		&testtxtmemoryisdpr,
		&testtxtdprislocked,
		&testhostbridgeDPRcorrect,
		&testhostbridgeDPRislocked,
		&testsinitintxt,
		&testsinitmatcheschipset,
		&testsinitmatchescpu,
		&testnosiniterrors,
		&testbiosdataregionpresent,
		&testbiosdataregionvalid,
		&testbiosdatanumlogprocsvalid,
		&testhasmtrr,
		&testhassmrr,
		&testvalidsmrr,
		&testactivesmrr,
		&testactiveiommi,
		&testactivetboot,
		&testservermodetext,
		&testreleasefusedfsbi,
	}
)

var (
	biosdata api.TXTBiosData
	//Heapsize from newer spec - Document 575623
	minHeapSize  = uint32(0xF0000)
	minSinitSize = uint32(0x50000)
	//Heapsize reduced for legacy spec - Document 558294
	legacyMinHeapSize = uint32(0xE0000)
)

func TestTXTRegisterSpaceValid() (bool, error, error) {
	buf, err := api.FetchTXTRegs()
	if err != nil {
		return false, nil, err
	}

	regs, err := api.ParseTXTRegs(buf)
	if err != nil {
		return false, nil, err
	}

	if uint64(regs.HeapBase) >= api.FourGiB {
		return false, fmt.Errorf("HeapBase > 4Gib"), nil
	}

	if uint64(regs.HeapBase+regs.HeapSize) >= api.FourGiB {
		return false, fmt.Errorf("HeapBase + HeapSize >= 4Gib"), nil
	}

	//TODO: Validate against minHeapSize once legacy detection is implemented

	//This checks for legacy heap size - Document 558294
	if regs.HeapSize < legacyMinHeapSize {
		return false, fmt.Errorf("Heap must be at least %v", legacyMinHeapSize), nil

	}

	if uint64(regs.SinitBase) >= api.FourGiB {
		return false, fmt.Errorf("SinitBase >= 4Gib"), nil
	}

	if uint64(regs.SinitBase+regs.SinitSize) >= api.FourGiB {
		return false, fmt.Errorf("SinitBase + SinitSize >= 4Gib"), nil
	}

	if regs.SinitSize < minSinitSize {
		return false, fmt.Errorf("Sinit must be at least %v", minSinitSize), nil
	}

	if uint64(regs.MleJoin) >= api.FourGiB {
		return false, fmt.Errorf("MleJoin >= 4Gib"), nil
	}

	if regs.SinitBase > regs.HeapBase {
		return false, fmt.Errorf("Sinit must be below Heapbase"), nil
	}

	return true, nil, nil
}

func TestTXTReservedInE820() (bool, error, error) {
	buf, err := api.FetchTXTRegs()
	if err != nil {
		return false, nil, err
	}
	regs, err := api.ParseTXTRegs(buf)
	if err != nil {
		return false, nil, err
	}

	heapReserved, err := api.IsReservedInE810(uint64(regs.HeapBase), uint64(regs.HeapBase+regs.HeapSize))
	if err != nil {
		return false, nil, err
	}

	sinitReserved, err := api.IsReservedInE810(uint64(regs.SinitBase), uint64(regs.SinitBase+regs.SinitSize))
	if err != nil {
		return false, nil, err
	}

	return heapReserved && sinitReserved, nil, nil
}

func TestTXTMemoryIsDPR() (bool, error, error) {
	buf, err := api.FetchTXTRegs()
	if err != nil {
		return false, nil, err
	}
	regs, err := api.ParseTXTRegs(buf)
	if err != nil {
		return false, nil, err
	}

	var memBase uint32
	var memLimit uint32

	var dprBase uint32
	var dprSize uint32
	var dprLimit uint32

	if regs.HeapBase > regs.SinitBase {
		memBase = regs.SinitBase
	} else {
		memBase = regs.HeapBase
	}

	if regs.HeapBase+regs.HeapSize > regs.SinitBase+regs.SinitSize {
		memLimit = regs.HeapBase + regs.HeapSize
	} else {
		memLimit = regs.SinitBase + regs.SinitSize
	}

	dprSize = uint32(regs.Dpr.Size) * 1024 * 1024
	dprLimit = uint32(regs.Dpr.Top+1) * 1024 * 1024
	dprBase = dprLimit - dprSize

	if memBase < dprBase {
		return false, fmt.Errorf("DPR doesn't protect bottom of TXT memory"), nil
	}
	if memLimit > dprLimit {
		return false, fmt.Errorf("DPR doesn't protect top of TXT memory"), nil
	}

	return true, nil, nil
}

func TestTXTDPRisLock() (bool, error, error) {
	buf, err := api.FetchTXTRegs()
	if err != nil {
		return false, nil, err
	}
	regs, err := api.ParseTXTRegs(buf)
	if err != nil {
		return false, nil, err
	}

	if regs.Dpr.Lock != true {
		return false, fmt.Errorf("TXTDPR is locked"), nil
	}
	return true, nil, nil
}

func TestHostbridgeDPRCorrect() (bool, error, error) {
	buf, err := api.FetchTXTRegs()
	if err != nil {
		return false, nil, err
	}
	regs, err := api.ParseTXTRegs(buf)
	if err != nil {
		return false, nil, err
	}

	hostbridgeDpr, err := api.ReadHostBridgeDPR()
	if err != nil {
		return false, nil, err
	}

	// No need to validate hostbridge register, already done for TXT DPR
	// Just make sure they match.

	if hostbridgeDpr.Top != regs.Dpr.Top {
		return false, fmt.Errorf("Hostbridge DPR Top doesn't match TXT DPR Top"), nil
	}

	if hostbridgeDpr.Size != regs.Dpr.Size {
		return false, fmt.Errorf("Hostbridge DPR Size doesn't match TXT DPR Size"), nil
	}

	return true, nil, nil
}

func TestHostbridgeDPRisLocked() (bool, error, error) {
	hostbridgeDpr, err := api.ReadHostBridgeDPR()
	if err != nil {
		return false, nil, err
	}

	if !hostbridgeDpr.Lock {
		return false, nil, fmt.Errorf("Hostbridge DPR isn't locked")
	}

	return true, nil, nil
}

func TestSINITInTXT() (bool, error, error) {
	buf, err := api.FetchTXTRegs()
	if err != nil {
		return false, nil, err
	}
	regs, err := api.ParseTXTRegs(buf)
	if err != nil {
		return false, nil, err
	}

	sinitBuf := make([]byte, regs.SinitSize)
	err = api.ReadPhysBuf(int64(regs.SinitBase), sinitBuf)
	if err != nil {
		return false, nil, err
	}

	acm, _, _, _, err := api.ParseACM(sinitBuf)
	if err != nil {
		return false, nil, err
	}
	if acm == nil {
		return false, fmt.Errorf("ACM is nil"), nil
	}

	if acm.Header.ModuleType != 2 {
		return false, fmt.Errorf("SINIT in TXT: ACM ModuleType not 2"), nil
	}
	return true, nil, nil

}

func TestSINITMatchesChipset() (bool, error, error) {
	buf, err := api.FetchTXTRegs()
	if err != nil {
		return false, nil, err
	}
	regs, err := api.ParseTXTRegs(buf)
	if err != nil {
		return false, nil, err
	}

	acm, chps, _, _, err := sinitACM(regs)
	if err != nil {
		return false, nil, err
	}
	if chps == nil {
		return false, fmt.Errorf("CHPS is nil"), nil
	}

	for _, ch := range chps.IDList {
		a := ch.VendorID == regs.Vid
		b := ch.DeviceID == regs.Did

		if a && b {
			if acm.Header.Flags&1 != 0 {
				if ch.RevisionID&regs.Rid == regs.Rid {
					return true, nil, nil
				}
			} else {
				if ch.RevisionID == regs.Rid {
					return true, nil, nil
				}
			}
		}
	}

	return false, fmt.Errorf("SINIT doesn't match chipset"), nil
}

func TestSINITMatchesCPU() (bool, error, error) {
	buf, err := api.FetchTXTRegs()
	if err != nil {
		return false, nil, err
	}
	regs, err := api.ParseTXTRegs(buf)
	if err != nil {
		return false, nil, err
	}

	_, _, cpus, _, err := sinitACM(regs)
	if err != nil {
		return false, nil, err
	}

	// IA32_PLATFORM_ID
	platform, err := api.IA32PlatformID()
	if err != nil {
		return false, nil, err
	}

	fms := api.CPUSignature()

	for _, cpu := range cpus.IDList {
		a := fms&cpu.FMSMask == cpu.FMS
		b := platform&cpu.PlatformMask == cpu.PlatformID

		if a && b {
			return true, nil, nil
		}
	}

	return false, fmt.Errorf("Sinit doesn't match CPU"), nil
}

func TestNoSINITErrors() (bool, error, error) {
	buf, err := api.FetchTXTRegs()
	if err != nil {
		return false, nil, err
	}
	regs, err := api.ParseTXTRegs(buf)
	if err != nil {
		return false, nil, err
	}

	if regs.ErrorCodeRaw != 0xc0000001 {
		return false, fmt.Errorf("SINIT Error detected"), nil
	}
	return true, nil, nil
}

func TestBIOSDATAREGIONPresent() (bool, error, error) {
	buf, err := api.FetchTXTRegs()
	if err != nil {
		return false, nil, err
	}
	regs, err := api.ParseTXTRegs(buf)
	if err != nil {
		return false, nil, err
	}

	txtHeap := make([]byte, regs.HeapSize)
	err = api.ReadPhysBuf(int64(regs.HeapBase), txtHeap)
	if err != nil {
		return false, nil, err
	}

	biosdata, err = api.ParseBIOSDataRegion(txtHeap)
	if err != nil {
		return false, nil, err
	}

	return true, nil, nil
}

func TestBIOSDATAREGIONValid() (bool, error, error) {
	if biosdata.Version < 2 {
		return false, fmt.Errorf("BIOS DATA regions version < 2 are not supperted"), nil
	}

	if biosdata.BiosSinitSize < 8 {
		return false, fmt.Errorf("BIOS DATA region is too small"), nil
	}

	if biosdata.NumLogProcs == 0 {
		return false, fmt.Errorf("BIOS DATA region corrupted"), nil
	}
	return true, nil, nil
}

func TestBIOSDATANumLogProcsValid() (bool, error, error) {
	if biosdata.NumLogProcs != api.CPULogCount() {
		return false, fmt.Errorf("Logical CPU count in BIOSData and CPUID doesn't match"), nil
	}
	return true, nil, nil
}

func TestHasMTRR() (bool, error, error) {
	if api.HasMTRR() != true {
		return false, fmt.Errorf("CPU does not have MTRR"), nil
	}
	return true, nil, nil
}

func TestHasSMRR() (bool, error, error) {
	ret, err := api.HasSMRR()
	if err != nil {
		return false, nil, err
	}
	if ret != true {
		return false, fmt.Errorf("CPU has no SMRR"), nil
	}
	return true, nil, nil
}

func TestValidSMRR() (bool, error, error) {
	smrr, err := api.GetSMRRInfo()
	if err != nil {
		return false, nil, err
	}

	if smrr.PhysMask == 0 {
		return false, fmt.Errorf("SMRR PhysMask isn't set"), nil
	}
	if smrr.PhysBase == 0 {
		return false, fmt.Errorf("SMRR PhysBase isn't set"), nil
	}

	tsegbase, tseglimit, err := api.ReadHostBridgeTseg()
	if err != nil {
		return false, nil, err
	}
	if tsegbase == 0 || tsegbase == 0xffffffff {
		return false, fmt.Errorf("TSEG base register isn't valid"), nil
	}
	if tseglimit == 0 || tseglimit == 0xffffffff {
		return false, fmt.Errorf("TSEG limit register isn't valid"), nil
	}

	if tsegbase&(^(uint32(smrr.PhysMask) << 12)) != 0 {
		return false, fmt.Errorf("TSEG base isn't aligned to SMRR Physmask"), nil
	}
	if tsegbase != (uint32(smrr.PhysBase) << 12) {
		return false, fmt.Errorf("TSEG base doesn't start at SMRR PhysBase"), nil
	}
	if tseglimit&(^(uint32(smrr.PhysMask) << 12)) != 0 {
		return false, fmt.Errorf("TSEG limit isn't aligned to SMRR Physmask"), nil
	}
	if ((tseglimit - 1) & (uint32(smrr.PhysMask) << 12)) != (uint32(smrr.PhysBase) << 12) {
		return false, fmt.Errorf("SMRR Physmask doesn't cover whole TSEG"), nil
	}

	return true, nil, nil
}

func TestActiveSMRR() (bool, error, error) {
	smrr, err := api.GetSMRRInfo()
	if err != nil {
		return false, nil, err
	}

	if smrr.Active != true {
		return false, fmt.Errorf("SMRR not active"), nil
	}
	return true, nil, nil
}

func TestActiveIOMMU() (bool, error, error) {
	smrr, err := api.GetSMRRInfo()
	if err != nil {
		return false, nil, err
	}
	ret, err := api.AddressRangesIsDMAProtected(smrr.PhysBase, smrr.PhysBase|^smrr.PhysMask)
	if err != nil {
		return false, nil, err
	}
	if ret != true {
		return false, fmt.Errorf("IOMMU not active"), nil
	}
	return true, nil, nil
}

func TestActiveTBOOT() (bool, error, error) {
	return false, nil, fmt.Errorf("TestActiveTBOOT: Unimplemented")
}

func TestServerModeTXT() (bool, error, error) {
	// FIXME: Query GetSec[Parameters] ebx = 5
	// Assume yes if dependencies are satisfied
	val, err := api.HasSMRR()
	if err != nil {
		return false, nil, err
	}
	if api.HasSMX() && api.HasVMX() && val {
		return true, nil, nil
	}
	return false, fmt.Errorf("Servermode not active"), nil
}

func TestReleaseFusedFSBI() (bool, error, error) {
	return false, nil, fmt.Errorf("TestReleaseFusedFSBI: Unimplemented")
}

func sinitACM(regs api.TXTRegisterSpace) (*api.ACM, *api.Chipsets, *api.Processors, *api.TPMs, error) {
	sinitBuf := make([]byte, regs.SinitSize)
	err := api.ReadPhysBuf(int64(regs.SinitBase), sinitBuf)
	if err != nil {
		return nil, nil, nil, nil, err
	}

	return api.ParseACM(sinitBuf)
}
