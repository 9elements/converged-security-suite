package test

import (
	"fmt"
	"github.com/9elements/txt-suite/pkg/api"
)

var (
	TestsMemory = [...]Test{
		Test{
			name:     "Intel TXT memory is reserved in e820",
			required: true,
			function: Test36TXTReservedInE820,
		},
		Test{
			name:     "Intel TXT memory is in a DMA protected range",
			required: true,
			function: Test37TXTMemoryIsDPR,
		},
		Test{
			name:     "CPU DMA protected range equals hostbridge DPR",
			required: true,
			function: Test38HostbridgeDPRCorrect,
		},
		Test{
			name:     "TXT region contains SINIT ACM",
			required: true,
			function: Test39SINITInTXT,
		},
		Test{
			name:     "SINIT ACM matches chipset",
			required: true,
			function: Test40SINITMatchesChipset,
		},
		Test{
			name:     "SINIT ACM matches CPU",
			required: true,
			function: Test41SINITMatchesCPU,
		},
		Test{
			name:     "SINIT ACM had no startup errors",
			required: true,
			function: Test42NoSINITErrors,
		},
		Test{
			name:     "BIOS DATA REGION is valid",
			required: true,
			function: Test43BIOSDATAREGIONPresent,
		},
		Test{
			name:     "CPU supports memory type range registers",
			required: true,
			function: Test44HasMTRR,
		},
		Test{
			name:     "CPU supports system management range registers",
			required: true,
			function: Test45HasSMRR,
		},
		Test{
			name:     "SMRR covers SMM memory",
			required: true,
			function: Test46ValidSMRR,
		},
		Test{
			name:     "SMRR protection is active",
			required: true,
			function: Test47ActiveSMRR,
		},
		Test{
			name:     "IOMMU/VT-d is active",
			required: true,
			function: Test48ActiveIOMMU,
		},
		Test{
			name:     "TBOOT hypervisor active",
			required: true,
			function: Test49ActiveTBOOT,
		},
		Test{
			name:     "Intel TXT server mode enabled",
			required: true,
			function: Test50ServerModeTXT,
		},
		Test{
			name:     "FSB interface is release fused",
			required: true,
			function: Test51ReleaseFusedFSBI,
		},
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

	return memBase-memLimit >= uint32(regs.Dpr.Size)*1024*1024 && regs.Dpr.Lock, nil
}

func Test38HostbridgeDPRCorrect() (bool, error) {
	return false, fmt.Errorf("Unimplemented")
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

	fms := api.FamilyModelStepping()

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

	return smrr.PhysBase > 0 && smrr.PhysBase <= 0xffffffff  && smrr.PhysMask = 0, nil
}

func Test47ActiveSMRR() (bool, error) {
	smrr, err := api.GetSMRRInfo()
	if err != nil {
		return false, err
	}

	return smrr.Active, nil
}

func Test48ActiveIOMMU() (bool, error) {
	return false, fmt.Errorf("Unimplemented")
}

func Test49ActiveTBOOT() (bool, error) {
	return false, fmt.Errorf("Unimplemented")
}

func Test50ServerModeTXT() (bool, error) {
	return false, fmt.Errorf("Unimplemented")
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
