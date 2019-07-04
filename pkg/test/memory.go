package test

import (
	"fmt"
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
	return false, fmt.Errorf("Unimplemented")
}

func Test37TXTMemoryIsDPR() (bool, error) {
	return false, fmt.Errorf("Unimplemented")
}

func Test38HostbridgeDPRCorrect() (bool, error) {
	return false, fmt.Errorf("Unimplemented")
}

func Test39SINITInTXT() (bool, error) {
	return false, fmt.Errorf("Unimplemented")
}

func Test40SINITMatchesChipset() (bool, error) {
	return false, fmt.Errorf("Unimplemented")
}

func Test41SINITMatchesCPU() (bool, error) {
	return false, fmt.Errorf("Unimplemented")
}

func Test42NoSINITErrors() (bool, error) {
	return false, fmt.Errorf("Unimplemented")
}

func Test43BIOSDATAREGIONPresent() (bool, error) {
	return false, fmt.Errorf("Unimplemented")
}

func Test44HasMTRR() (bool, error) {
	return false, fmt.Errorf("Unimplemented")
}

func Test45HasSMRR() (bool, error) {
	return false, fmt.Errorf("Unimplemented")
}

func Test46ValidSMRR() (bool, error) {
	return false, fmt.Errorf("Unimplemented")
}

func Test47ActiveSMRR() (bool, error) {
	return false, fmt.Errorf("Unimplemented")
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
