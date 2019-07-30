package test

import (
	"fmt"

	"github.com/9elements/txt-suite/pkg/api"
)

var (
	test36memoryisreserved = Test{
		Name:     "Intel TXT memory is reserved in e820",
		Required: true,
		function: Test36TXTReservedInE820,
	}
	test37txtmemoryisdpr = Test{
		Name:     "Intel TXT memory is in a DMA protected range",
		Required: true,
		function: Test37TXTMemoryIsDPR,
	}
	testtxtdprislocked = Test{
		Name:     "Intel TXT DPR register is locked",
		Required: true,
		function: TestTXTDPRisLock,
	}
	test38hostbridgeDPRcorrect = Test{
		Name:     "CPU DMA protected range equals hostbridge DPR",
		Required: false,
		function: Test38HostbridgeDPRCorrect,
	}
	testhostbridgeDPRislocked = Test{
		Name:     "CPU hostbridge DPR register is locked",
		Required: true,
		function: TestHostbridgeDPRisLocked,
	}
	test39sinitintxt = Test{
		Name:     "TXT region contains SINIT ACM",
		Required: true,
		function: Test39SINITInTXT,
	}
	test40sinitmatcheschipset = Test{
		Name:         "SINIT ACM matches chipset",
		Required:     true,
		function:     Test40SINITMatchesChipset,
		dependencies: []*Test{&test39sinitintxt},
	}
	test41sinitmatchescpu = Test{
		Name:         "SINIT ACM matches CPU",
		Required:     true,
		function:     Test41SINITMatchesCPU,
		dependencies: []*Test{&test39sinitintxt},
	}
	test42nosiniterrors = Test{
		Name:     "SINIT ACM had no startup errors",
		Required: false,
		function: Test42NoSINITErrors,
	}
	test43biosdataregionpresent = Test{
		Name:     "BIOS DATA REGION is valid",
		Required: true,
		function: Test43BIOSDATAREGIONPresent,
	}
	test44hasmtrr = Test{
		Name:     "CPU supports memory type range registers",
		Required: true,
		function: Test44HasMTRR,
	}
	test45hassmrr = Test{
		Name:         "CPU supports system management range registers",
		Required:     true,
		function:     Test45HasSMRR,
		dependencies: []*Test{&test50servermodetext},
	}
	test46validsmrr = Test{
		Name:         "SMRR covers SMM memory",
		Required:     true,
		function:     Test46ValidSMRR,
		dependencies: []*Test{&test45hassmrr},
	}
	test47activesmrr = Test{
		Name:         "SMRR protection is active",
		Required:     true,
		function:     Test47ActiveSMRR,
		dependencies: []*Test{&test45hassmrr},
	}
	test48activeiommi = Test{
		Name:     "IOMMU/VT-d is active",
		Required: false,
		function: Test48ActiveIOMMU,
	}
	test49activetboot = Test{
		Name:     "TBOOT hypervisor active",
		Required: false,
		function: Test49ActiveTBOOT,
	}
	test50servermodetext = Test{
		Name:     "Intel TXT server mode enabled",
		Required: false,
		function: Test50ServerModeTXT,
	}
	test51releasefusedfsbi = Test{
		Name:     "FSB interface is release fused",
		Required: false,
		function: Test51ReleaseFusedFSBI,
	}

	TestsMemory = [...]*Test{
		&test36memoryisreserved,
		&test37txtmemoryisdpr,
		&testtxtdprislocked,
		&test38hostbridgeDPRcorrect,
		&testhostbridgeDPRislocked,
		&test39sinitintxt,
		&test40sinitmatcheschipset,
		&test41sinitmatchescpu,
		&test42nosiniterrors,
		&test43biosdataregionpresent,
		&test44hasmtrr,
		&test45hassmrr,
		&test46validsmrr,
		&test47activesmrr,
		&test48activeiommi,
		&test49activetboot,
		&test50servermodetext,
		&test51releasefusedfsbi,
	}
)

func Test36TXTReservedInE820() (bool, error) {
	regs, err := api.ReadTXTRegs()
	if err != nil {
		return false, err
	}

	heapReserved, err := api.IsReservedInE810(uint64(regs.HeapBase), uint64(regs.HeapBase+regs.HeapSize))
	if err != nil {
		return false, err
	}

	sinitReserved, err := api.IsReservedInE810(uint64(regs.SinitBase), uint64(regs.SinitBase+regs.SinitSize))
	if err != nil {
		return false, err
	}

	return heapReserved && sinitReserved, nil
}

func Test37TXTMemoryIsDPR() (bool, error) {
	regs, err := api.ReadTXTRegs()
	if err != nil {
		return false, err
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
		return false, fmt.Errorf("DPR doesn't protect bottom of TXT memory")
	}
	if memLimit > dprLimit {
		return false, fmt.Errorf("DPR doesn't protect top of TXT memory")
	}

	return true, nil
}

func TestTXTDPRisLock() (bool, error) {
	regs, err := api.ReadTXTRegs()
	if err != nil {
		return false, err
	}

	return regs.Dpr.Lock, nil
}

func Test38HostbridgeDPRCorrect() (bool, error) {
	regs, err := api.ReadTXTRegs()
	if err != nil {
		return false, err
	}

	hostbridgeDpr, err := api.ReadHostBridgeDPR()
	if err != nil {
		return false, err
	}

	// No need to validate hostbridge register, already done for TXT DPR
	// Just make sure they match.

	if hostbridgeDpr.Top != regs.Dpr.Top {
		return false, fmt.Errorf("Hostbridge DPR Top doesn't match TXT DPR Top")
	}

	if hostbridgeDpr.Size != regs.Dpr.Size {
		return false, fmt.Errorf("Hostbridge DPR Size doesn't match TXT DPR Size")
	}

	return true, nil
}

func TestHostbridgeDPRisLocked() (bool, error) {
	hostbridgeDpr, err := api.ReadHostBridgeDPR()
	if err != nil {
		return false, err
	}

	if !hostbridgeDpr.Lock {
		return false, fmt.Errorf("Hostbridge DPR isn't locked")
	}

	return true, nil
}

func Test39SINITInTXT() (bool, error) {
	regs, err := api.ReadTXTRegs()
	if err != nil {
		return false, err
	}

	sinitBuf := make([]byte, regs.SinitSize)
	err = api.ReadPhysBuf(int64(regs.SinitBase), sinitBuf)
	if err != nil {
		return false, err
	}

	acm, _, _, _, err := api.ParseACM(sinitBuf)
	if err != nil || acm == nil {
		return false, err
	}

	return acm.ModuleType == 2, nil
}

func Test40SINITMatchesChipset() (bool, error) {
	regs, err := api.ReadTXTRegs()
	if err != nil {
		return false, err
	}

	acm, chps, _, _, err := sinitACM(regs)
	if err != nil || chps == nil {
		return false, err
	}

	for _, ch := range chps.IDList {
		a := ch.VendorID == regs.Vid
		b := ch.DeviceID == regs.Did

		if a && b {
			if acm.Flags&1 != 0 {
				if ch.RevisionID&regs.Rid == regs.Rid {
					return true, nil
				}
			} else {
				if ch.RevisionID == regs.Rid {
					return true, nil
				}
			}
		}
	}

	return false, nil
}

func Test41SINITMatchesCPU() (bool, error) {
	regs, err := api.ReadTXTRegs()
	if err != nil {
		return false, err
	}

	_, _, cpus, _, err := sinitACM(regs)
	if err != nil {
		return false, err
	}

	// IA32_PLATFORM_ID
	platform, err := api.IA32PlatformID()
	if err != nil {
		return false, err
	}

	fms := api.CPUSignature()

	for _, cpu := range cpus.IDList {
		a := fms&cpu.FMSMask == cpu.FMS
		b := platform&cpu.PlatformMask == cpu.PlatformID

		if a && b {
			return true, nil
		}
	}

	return false, nil
}

func Test42NoSINITErrors() (bool, error) {
	regs, err := api.ReadTXTRegs()
	if err != nil {
		return false, err
	}

	return regs.ErrorCodeRaw == 0xc0000001, nil
}

func Test43BIOSDATAREGIONPresent() (bool, error) {
	regs, err := api.ReadTXTRegs()
	if err != nil {
		return false, err
	}

	txtHeap := make([]byte, regs.HeapSize)
	err = api.ReadPhysBuf(int64(regs.HeapBase), txtHeap)
	if err != nil {
		return false, err
	}

	_, err = api.ParseBIOSDataRegion(txtHeap)
	if err != nil {
		return false, err
	}

	return true, nil
}

func Test44HasMTRR() (bool, error) {
	return api.HasMTRR(), nil
}

func Test45HasSMRR() (bool, error) {
	return api.HasSMRR()
}

func Test46ValidSMRR() (bool, error) {
	smrr, err := api.GetSMRRInfo()
	if err != nil {
		return false, err
	}

	if smrr.PhysMask == 0 {
		return false, fmt.Errorf("SMRR PhysMask isn't set")
	}
	if smrr.PhysBase == 0 {
		return false, fmt.Errorf("SMRR PhysBase isn't set")
	}

	tsegbase, tseglimit, err := api.ReadHostBridgeTseg()
	if err != nil {
		return false, err
	}
	if tsegbase == 0 || tsegbase == 0xffffffff {
		return false, fmt.Errorf("TSEG base register isn't valid")
	}
	if tseglimit == 0 || tseglimit == 0xffffffff {
		return false, fmt.Errorf("TSEG limit register isn't valid")
	}

	if tsegbase&(^(uint32(smrr.PhysMask) << 12)) != 0 {
		return false, fmt.Errorf("TSEG base isn't aligned to SMRR Physmask")
	}
	if tsegbase != (uint32(smrr.PhysBase) << 12) {
		return false, fmt.Errorf("TSEG base doesn't start at SMRR PhysBase")
	}
	if tseglimit&(^(uint32(smrr.PhysMask) << 12)) != 0 {
		return false, fmt.Errorf("TSEG limit isn't aligned to SMRR Physmask")
	}
	if ((tseglimit - 1) & (uint32(smrr.PhysMask) << 12)) != (uint32(smrr.PhysBase) << 12) {
		return false, fmt.Errorf("SMRR Physmask doesn't cover whole TSEG")
	}

	return true, nil
}

func Test47ActiveSMRR() (bool, error) {
	smrr, err := api.GetSMRRInfo()
	if err != nil {
		return false, err
	}

	return smrr.Active, nil
}

func Test48ActiveIOMMU() (bool, error) {
	smrr, err := api.GetSMRRInfo()
	if err != nil {
		return false, err
	}

	return api.AddressRangesIsDMAProtected(smrr.PhysBase, smrr.PhysBase|^smrr.PhysMask)
}

func Test49ActiveTBOOT() (bool, error) {
	return false, fmt.Errorf("Unimplemented")
}

func Test50ServerModeTXT() (bool, error) {
	// FIXME: Query GetSec[Parameters] ebx = 5
	// Assume yes if dependencies are satisfied
	val, err := api.HasSMRR()
	if err != nil {
		return false, err
	}
	return api.HasSMX() && api.HasVMX() && val, nil
}

func Test51ReleaseFusedFSBI() (bool, error) {
	return false, fmt.Errorf("Unimplemented")
}

func sinitACM(regs api.TXTRegisterSpace) (*api.ACM, *api.Chipsets, *api.Processors, *api.TPMs, error) {
	sinitBuf := make([]byte, regs.SinitSize)
	err := api.ReadPhysBuf(int64(regs.SinitBase), sinitBuf)
	if err != nil {
		return nil, nil, nil, nil, err
	}

	return api.ParseACM(sinitBuf)
}
