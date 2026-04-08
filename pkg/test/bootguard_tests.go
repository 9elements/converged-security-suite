package test

import (
	"bytes"
	"fmt"

	"github.com/9elements/converged-security-suite/v2/pkg/intel"
	"github.com/9elements/converged-security-suite/v2/pkg/provisioning/bootguard"
	"github.com/9elements/converged-security-suite/v2/pkg/tools"
	"github.com/9elements/go-linux-lowlevel-hw/pkg/hwapi"
	"github.com/linuxboot/fiano/pkg/intel/metadata/fit"
)

const (
	IntelBootGuardSpecificationTitle      = "Intel Converged Boot Guard and Intel Trustetestbootguardmeconfigd Execution Technology"
	IntelBootGuardSpecificationDocumentID = "557867 / 575623"
)

var (
	legacy = []intel.BgVersion{intel.BootGuard, intel.CBnT20}
	cbnt21 = []intel.BgVersion{intel.CBnT21}
	all    = []intel.BgVersion{intel.BootGuard, intel.CBnT20, intel.CBnT21}

	testbootguardfit = Test{
		Name:                    "FIT meets BootGuard requirements",
		Description:             "Checks FIT has all required Boot Guard records (ACM, BPM, and KM).",
		Required:                true,
		function:                BootGuardFIT,
		Status:                  Implemented,
		SpecificationChapter:    "",
		SpecificiationTitle:     IntelFITSpecificationTitle,
		SpecificationDocumentID: IntelFITSpecificationDocumentID,
	}
	testbootguardacm = Test{
		Name:                    "SACM meets sane BootGuard requirements",
		Description:             "Parses SACM and validates production mode, ACM type, and optional chipset match.",
		Required:                true,
		function:                BootGuardACM,
		dependencies:            []*Test{&testbootguardfit},
		Status:                  Implemented,
		SpecificationChapter:    "Chapter A. Authenticated Code Modules",
		SpecificiationTitle:     IntelTXTSpecificationTitle,
		SpecificationDocumentID: IntelTXTSpecificationDocumentID,
	}
	testbootguardkm = Test{
		Name:                    "Key Manifest meets sane BootGuard requirements",
		Description:             "Parses Key Manifest and validates signature, crypto safety, and BPM hash presence.",
		Required:                true,
		function:                BootGuardKM,
		dependencies:            []*Test{&testbootguardfit},
		Status:                  Implemented,
		SpecificationChapter:    "",
		SpecificiationTitle:     IntelBootGuardSpecificationTitle,
		SpecificationDocumentID: IntelBootGuardSpecificationDocumentID,
	}
	testbootguardbpm = Test{
		Name:                    "Boot Policy Manifest meets sane BootGuard requirements",
		Description:             "Parses BPM/KM and validates BPM structure, signature, security properties, and KM binding.",
		Required:                true,
		function:                BootGuardBPM,
		dependencies:            []*Test{&testbootguardfit},
		Status:                  Implemented,
		SpecificationChapter:    "",
		SpecificiationTitle:     IntelBootGuardSpecificationTitle,
		SpecificationDocumentID: IntelBootGuardSpecificationDocumentID,
	}
	testbootguardibb = Test{
		Name:                    "Verifies BPM and IBBs match firmware image",
		Description:             "Verifies measured IBBs from firmware match the BPM final IBB digest.",
		Required:                true,
		function:                BootGuardIBB,
		dependencies:            []*Test{&testbootguardfit},
		Status:                  Implemented,
		SpecificationChapter:    "",
		SpecificiationTitle:     IntelBootGuardSpecificationTitle,
		SpecificationDocumentID: IntelBootGuardSpecificationDocumentID,
	}
	testbootguardvalidateme = Test{
		Name:                    "[RUNTIME] Validates Intel ME specific configuration against KM/BPM in firmware image",
		Description:             "Compares runtime ME Boot Guard status against KM/BPM policy requirements.",
		Required:                true,
		function:                BootGuardValidateME,
		dependencies:            []*Test{&testbootguardfit},
		Status:                  Implemented,
		SpecificationChapter:    "",
		SpecificiationTitle:     IntelBootGuardSpecificationTitle,
		SpecificationDocumentID: IntelBootGuardSpecificationDocumentID,
		SupportedVersion:        legacy,
	}
	testbootguardmebootguardsts = Test{
		Name:                    "[RUNTIME] Verifies Intel ME Boot Guard status",
		Description:             "Reads Boot Guard related information from ME and checks if they are sane (requires ME 18/21)",
		Required:                true,
		function:                BootGuardMESts,
		dependencies:            []*Test{&testbootguardfit},
		Status:                  Implemented,
		SpecificationChapter:    "",
		SpecificiationTitle:     "Intel Converged Security and Management Engine 18.x/19.x BIOS Specification / Intel Converged Security and Management Engine 21.0",
		SpecificationDocumentID: "729124 / 829718",
		SupportedVersion:        cbnt21,
	}
	testbootguardsanemeconfig = Test{
		Name:                    "[RUNTIME] Verifies Intel ME Boot Guard configuration is sane and safe",
		Description:             "Checks runtime ME Boot Guard provisioning state is sane (strict or relaxed profile).",
		Required:                true,
		function:                BootGuardSaneMEConfig,
		Status:                  Implemented,
		SpecificationChapter:    "",
		SpecificiationTitle:     IntelBootGuardSpecificationTitle,
		SpecificationDocumentID: IntelBootGuardSpecificationDocumentID,
		SupportedVersion:        all,
	}
	testbootguardbgacmsts = Test{
		Name:                    "[RUNTIME] Verifies post-boot ACM status",
		Description:             "Validates runtime TXT registers for a secure post-boot ACM status.",
		Required:                true,
		function:                BootGuardTXTACMSts,
		Status:                  Implemented,
		SpecificationChapter:    "",
		SpecificiationTitle:     IntelTXTSpecificationTitle,
		SpecificationDocumentID: IntelTXTSpecificationDocumentID,
		SupportedVersion:        legacy,
	}
	testbootguardtxtsts = Test{
		Name:                    "[RUNTIME] Verifies post-boot BtG/TXT registers",
		Description:             "Validates runtime TXT/Boot Guard registers for a secure post boot status.",
		Required:                true,
		function:                BootGuardTXTRegisters,
		Status:                  Implemented,
		SpecificationChapter:    "",
		SpecificiationTitle:     IntelTXTSpecificationTitle,
		SpecificationDocumentID: IntelTXTSpecificationDocumentID,
		SupportedVersion:        all,
	}
	// TestsMemory exposes the slice for memory related txt tests
	TestsBootGuard = [...]*Test{
		&testbootguardfit,
		&testbootguardacm,
		&testbootguardkm,
		&testbootguardbpm,
		&testbootguardibb,
		&testbootguardvalidateme,
		&testbootguardmebootguardsts,
		&testbootguardsanemeconfig,
		&testbootguardbgacmsts,
		&testbootguardtxtsts,
	}
)

// BootGuardFIT checks FIT requirements for safe BootGuard configuration
func BootGuardFIT(hw hwapi.LowLevelHardwareInterfaces, p *PreSet) (bool, error, error) {
	entries, err := fit.GetEntries(p.Firmware)
	if err != nil {
		return false, fmt.Errorf("couldn't parse FIT"), err
	}
	var hasACM, hasBPM, hasKM bool
	for _, entry := range entries {
		switch entry.(type) {
		case *fit.EntrySACM:
			hasACM = true
		case *fit.EntryBootPolicyManifestRecord:
			hasBPM = true
		case *fit.EntryKeyManifestRecord:
			hasKM = true
		}
	}
	if !hasACM {
		return false, fmt.Errorf("couldn't find BIOS ACM in FIT"), nil
	}
	if !hasBPM {
		return false, fmt.Errorf("couldn't find BPM in FIT"), nil
	}
	if !hasKM {
		return false, fmt.Errorf("couldn't find KM in FIT"), nil
	}
	return true, nil, nil
}

// BootGuardACM checks ACM requirements for safe BootGuard configuration
func BootGuardACM(hw hwapi.LowLevelHardwareInterfaces, p *PreSet) (bool, error, error) {
	entries, err := fit.GetEntries(p.Firmware)
	if err != nil {
		return false, fmt.Errorf("couldn't parse FIT"), err
	}
	var acm *tools.ACM
	for _, entry := range entries {
		switch entry := entry.(type) {
		case *fit.EntrySACM:
			r := bytes.NewReader(entry.DataSegmentBytes)
			acm, err = tools.ParseACM(r)
			if err != nil {
				return false, fmt.Errorf("couldn't parse SACM"), err
			}
		}
	}
	// Checks ACM is production ACM
	if !acm.ParseACMFlags().Production {
		return false, fmt.Errorf("SACM is not production worthy"), nil
	}
	// Checks ACM is BIOS ACM
	if acm.Info.ChipsetACMType != tools.ACMChipsetTypeBios && acm.Info.ChipsetACMType != tools.ACMChipsetTypeBiosRevoc {
		return false, fmt.Errorf("SACM type is not BIOS"), nil
	}
	// Checks v3 ACMs
	if p.HostBridgeDeviceID != 0 && acm.UUID() == tools.ACMUUIDV3 {
		var match bool
		for _, ch := range acm.Chipsets.IDList {
			if ch.DeviceID == p.HostBridgeDeviceID {
				match = true
			}
		}
		if !match {
			return false, fmt.Errorf("SACM doesn't match target device ID"), nil
		}
	}
	return true, nil, nil
}

// BootGuardKM checks KM requirements for safe BootGuard configuration
func BootGuardKM(hw hwapi.LowLevelHardwareInterfaces, p *PreSet) (bool, error, error) {
	entries, err := fit.GetEntries(p.Firmware)
	if err != nil {
		return false, fmt.Errorf("couldn't parse FIT"), err
	}
	var b *bootguard.BootGuard
	for _, entry := range entries {
		switch entry := entry.(type) {
		case *fit.EntryKeyManifestRecord:
			r := bytes.NewReader(entry.DataSegmentBytes)
			b, err = bootguard.NewKM(r)
		}
	}
	if b == nil || err != nil {
		return false, fmt.Errorf("couldn't parse KM"), err
	}
	if err := b.ValidateKM(); err != nil {
		return false, fmt.Errorf("couldn't validate KM"), err
	}
	if err := b.VerifyKM(); err != nil {
		return false, fmt.Errorf("couldn't verify KM signature"), err
	}
	secure, err := b.KMCryptoSecure()
	if !secure || err != nil {
		return false, fmt.Errorf("km crypto parameters are insecure"), err
	}
	secure, err = b.KMHasBPMHash()
	if !secure || err != nil {
		return false, fmt.Errorf("km has no bpm hash"), err
	}
	return true, nil, nil
}

// BootGuardBPM checks BPM requirements for safe BootGuard configuration
func BootGuardBPM(hw hwapi.LowLevelHardwareInterfaces, p *PreSet) (bool, error, error) {
	entries, err := fit.GetEntries(p.Firmware)
	if err != nil {
		return false, fmt.Errorf("couldn't parse FIT"), err
	}
	var kmReader, bpmReader *bytes.Reader
	for _, entry := range entries {
		switch entry := entry.(type) {
		case *fit.EntryKeyManifestRecord:
			kmReader = bytes.NewReader(entry.DataSegmentBytes)
		case *fit.EntryBootPolicyManifestRecord:
			bpmReader = bytes.NewReader(entry.DataSegmentBytes)
		}
	}
	b, err := bootguard.NewBPMAndKM(bpmReader, kmReader)
	if b == nil || err != nil {
		return false, fmt.Errorf("couldn't parse KM and BPM"), err
	}
	if err := b.ValidateBPM(); err != nil {
		return false, fmt.Errorf("couldn't validate BPM"), err
	}
	if err := b.VerifyBPM(); err != nil {
		return false, fmt.Errorf("couldn't verify BPM signature"), err
	}
	secure, err := b.BPMCryptoSecure()
	if !secure || err != nil {
		return false, fmt.Errorf("bpm crypto parameters are insecure"), err
	}
	if p.Strict {
		secure, err = b.StrictSaneBPMSecurityProps()
	} else {
		secure, err = b.SaneBPMSecurityProps()
	}
	if !secure || err != nil {
		return false, fmt.Errorf("bpm hasn't sane security properties"), err
	}
	secure, err = b.BPMKeyMatchKMHash()
	if !secure || err != nil {
		return false, fmt.Errorf("bpm doesn't match km hash"), err
	}
	return true, nil, nil
}

// BootGuardIBB checks BPM IBB configuration can be validated against firmware image
func BootGuardIBB(hw hwapi.LowLevelHardwareInterfaces, p *PreSet) (bool, error, error) {
	entries, err := fit.GetEntries(p.Firmware)
	if err != nil {
		return false, fmt.Errorf("couldn't parse FIT"), err
	}
	var kmReader, bpmReader *bytes.Reader
	for _, entry := range entries {
		switch entry := entry.(type) {
		case *fit.EntryKeyManifestRecord:
			kmReader = bytes.NewReader(entry.DataSegmentBytes)
		case *fit.EntryBootPolicyManifestRecord:
			bpmReader = bytes.NewReader(entry.DataSegmentBytes)
		}
	}
	b, err := bootguard.NewBPMAndKM(bpmReader, kmReader)
	if b == nil || err != nil {
		return false, fmt.Errorf("couldn't parse KM and BPM"), err
	}
	secure, err := b.IBBsMatchBPMDigest(p.Firmware)
	if !secure || err != nil {
		return false, fmt.Errorf("measured ibb doesn't match bpm final ibb digest"), err
	}
	return true, nil, nil
}

// BootGuardValidateME
func BootGuardValidateME(hw hwapi.LowLevelHardwareInterfaces, p *PreSet) (bool, error, error) {
	entries, err := fit.GetEntries(p.Firmware)
	if err != nil {
		return false, fmt.Errorf("couldn't parse FIT"), err
	}
	var kmReader, bpmReader *bytes.Reader
	for _, entry := range entries {
		switch entry := entry.(type) {
		case *fit.EntryKeyManifestRecord:
			kmReader = bytes.NewReader(entry.DataSegmentBytes)
		case *fit.EntryBootPolicyManifestRecord:
			bpmReader = bytes.NewReader(entry.DataSegmentBytes)
		}
	}
	b, err := bootguard.NewBPMAndKM(bpmReader, kmReader)
	if b == nil || err != nil {
		return false, fmt.Errorf("couldn't parse KM and BPM"), err
	}
	hfsts, err := bootguard.NewFirmwareStatus(hw)
	if err != nil {
		return false, fmt.Errorf("couldn't read Intel ME firmware status"), err
	}
	valid, err := b.ValidateMEAgainstManifests(hfsts)
	if !valid || err != nil {
		return false, fmt.Errorf("bootguard km/bpm doesn't match ME BootGuard configuration"), err
	}
	return true, nil, nil
}

// BootGuardMESts
func BootGuardMESts(hw hwapi.LowLevelHardwareInterfaces, p *PreSet) (bool, error, error) {
	hfsts, err := bootguard.NewFirmwareStatus(hw)
	if err != nil {
		return false, fmt.Errorf("couldn't read Intel ME firmware status"), err
	}
	if !hfsts.Status5.BgACMStatus {
		return false, fmt.Errorf("acm is not active"), err
	}
	if hfsts.Status5.ErrorCode != 0 {
		return false, fmt.Errorf("bg startup failed"), err
	}
	if !hfsts.Status5.BPMExecStatus {
		return false, fmt.Errorf("bpm not executed"), err
	}
	if hfsts.Status5.BgStatus != 0x01 {
		return false, fmt.Errorf("bg status is invalid"), err
	}
	return true, nil, nil
}

// BootGuardSaneMEConfig
func BootGuardSaneMEConfig(hw hwapi.LowLevelHardwareInterfaces, p *PreSet) (bool, error, error) {
	entries, err := fit.GetEntries(p.Firmware)
	if err != nil {
		return false, fmt.Errorf("couldn't parse FIT"), err
	}
	var b *bootguard.BootGuard
	for _, entry := range entries {
		switch entry := entry.(type) {
		case *fit.EntryKeyManifestRecord:
			r := bytes.NewReader(entry.DataSegmentBytes)
			b, err = bootguard.NewKM(r)
		}
	}
	if b == nil || err != nil {
		return false, fmt.Errorf("couldn't parse KM"), err
	}

	hfsts, err := bootguard.NewFirmwareStatus(hw)
	if err != nil {
		return false, fmt.Errorf("couldn't read HFSTS6"), err
	}

	bgi, err := bootguard.GetBGInfo(hw)
	if err != nil {
		return false, fmt.Errorf("couldn't read Boot Guard runtime info"), err
	}

	if p.Strict {
		valid, err := bootguard.StrictSaneBootGuardProvisioning(b.Version, hfsts, bgi)
		if !valid || err != nil {
			return false, fmt.Errorf("provisiong boot guard configuraton in me isn't safe"), err
		}
	} else {
		valid, err := bootguard.SaneMEBootGuardProvisioning(b.Version, hfsts, bgi)
		if !valid || err != nil {
			return false, fmt.Errorf("provisiong boot guard configuraton in me isn't safe"), err
		}
	}
	return true, nil, nil
}

// BootGuardTXTACMSts checks TXT requirements for safe BootGuard configuration
func BootGuardTXTACMSts(hw hwapi.LowLevelHardwareInterfaces, p *PreSet) (bool, error, error) {
	valid, err := bootguard.ValidACMStatus(hw)
	if !valid || err != nil {
		return false, fmt.Errorf("txt regs aren't valid"), err
	}

	return true, nil, nil
}

// BootGuardTXTRegisters checks TXT requirements for safe BootGuard configuration
func BootGuardTXTRegisters(hw hwapi.LowLevelHardwareInterfaces, p *PreSet) (bool, error, error) {
	valid, err := bootguard.ValidTXTRegisters(hw)
	if !valid || err != nil {
		return false, fmt.Errorf("txt regs aren't valid"), err
	}

	return true, nil, nil
}
