package test

import (
	"bytes"
	"fmt"

	"github.com/9elements/converged-security-suite/v2/pkg/provisioning/bootguard"
	"github.com/9elements/converged-security-suite/v2/pkg/tools"
	"github.com/9elements/go-linux-lowlevel-hw/pkg/hwapi"
	"github.com/linuxboot/fiano/pkg/intel/metadata/fit"
	"go.uber.org/multierr"
)

const (
	IntelBootGuardSpecificationTitle      = "Intel Converged Boot Guard and Intel Trustetestbootguardmeconfigd Execution Technology"
	IntelBootGuardSpecificationDocumentID = "557867 / 575623"
)

var (
	testbootguardfit = Test{
		Name:                    "FIT meets BootGuard requirements",
		Required:                true,
		function:                BootGuardFIT,
		Status:                  Implemented,
		SpecificationChapter:    "",
		SpecificiationTitle:     IntelFITSpecificationTitle,
		SpecificationDocumentID: IntelFITSpecificationDocumentID,
	}
	testbootguardacm = Test{
		Name:                    "SACM meets sane BootGuard requirements",
		Required:                true,
		function:                BootGuardACM,
		Status:                  Implemented,
		SpecificationChapter:    "Chapter A. Authenticated Code Modules",
		SpecificiationTitle:     IntelTXTSpecificationTitle,
		SpecificationDocumentID: IntelTXTSpecificationDocumentID,
	}
	testbootguardkm = Test{
		Name:                    "Key Manifest meets sane BootGuard requirements",
		Required:                true,
		function:                BootGuardKM,
		Status:                  Implemented,
		SpecificationChapter:    "",
		SpecificiationTitle:     IntelBootGuardSpecificationTitle,
		SpecificationDocumentID: IntelBootGuardSpecificationDocumentID,
	}
	testbootguardbpm = Test{
		Name:                    "Boot Policy Manifest meets sane BootGuard requirements",
		Required:                true,
		function:                BootGuardBPM,
		Status:                  Implemented,
		SpecificationChapter:    "",
		SpecificiationTitle:     IntelBootGuardSpecificationTitle,
		SpecificationDocumentID: IntelBootGuardSpecificationDocumentID,
	}
	testbootguardibb = Test{
		Name:                    "Verifies BPM and IBBs match firmware image",
		Required:                true,
		function:                BootGuardIBB,
		Status:                  Implemented,
		SpecificationChapter:    "",
		SpecificiationTitle:     IntelBootGuardSpecificationTitle,
		SpecificationDocumentID: IntelBootGuardSpecificationDocumentID,
	}
	testbootguardvalidateme = Test{
		Name:                    "[RUNTIME] Validates Intel ME specific configuration against KM/BPM in firmware image",
		Required:                true,
		function:                BootGuardValidateME,
		dependencies:            []*Test{&testbootguardfit},
		Status:                  Implemented,
		SpecificationChapter:    "",
		SpecificiationTitle:     IntelBootGuardSpecificationTitle,
		SpecificationDocumentID: IntelBootGuardSpecificationDocumentID,
	}
	testbootguardsanemeconfig = Test{
		Name:                    "[RUNTIME] Verifies Intel ME Boot Guard configuration is sane and safe",
		Required:                true,
		function:                BootGuardSaneMEConfig,
		Status:                  Implemented,
		SpecificationChapter:    "",
		SpecificiationTitle:     IntelBootGuardSpecificationTitle,
		SpecificationDocumentID: IntelBootGuardSpecificationDocumentID,
	}
	testbootguardtxt = Test{
		Name:                    "[RUNTIME] BtG/TXT registers are sane",
		Required:                true,
		function:                BootGuardTXT,
		Status:                  Implemented,
		SpecificationChapter:    "",
		SpecificiationTitle:     IntelTXTSpecificationTitle,
		SpecificationDocumentID: IntelTXTSpecificationDocumentID,
	}

	// TestsMemory exposes the slice for memory related txt tests
	TestsBootGuard = [...]*Test{
		&testbootguardfit,
		&testbootguardacm,
		&testbootguardkm,
		&testbootguardbpm,
		&testbootguardibb,
		&testbootguardvalidateme,
		&testbootguardsanemeconfig,
		&testbootguardtxt,
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
	var errs error
	b, err := bootguard.NewBPMAndKM(bpmReader, kmReader)
	if b == nil || err != nil {
		errs = multierr.Combine(errs, fmt.Errorf("couldn't parse Key Manifest and Boot Policy Manifest\n"))
	}
	if err := b.ValidateBPM(); err != nil {
		errs = multierr.Combine(errs, fmt.Errorf("couldn't validate Boot Policy Manifest"))
	}
	if err := b.VerifyBPM(); err != nil {
		errs = multierr.Combine(errs, fmt.Errorf("couldn't verify Boot Policy Manifest signature"))
	}
	secure, err := b.BPMCryptoSecure()
	if !secure || err != nil {
		errs = multierr.Combine(errs, fmt.Errorf("Boot Policy Manifest crypto parameters are insecure"))
	}
	if p.Strict {
		secure, err = b.StrictSaneBPMSecurityProps()
	} else {
		secure, err = b.SaneBPMSecurityProps()
	}
	if !secure || err != nil {
		errs = multierr.Combine(errs, fmt.Errorf("Boot Policy Manifest doesn't have sane security properties: %v", err))
	}
	secure, err = b.BPMKeyMatchKMHash()
	if !secure || err != nil {
		errs = multierr.Combine(errs, fmt.Errorf("Boot Policy Manifest doesn't match Key Manifest hash: %v", err))
	}
	if errs != nil {
		return false, fmt.Errorf("Errors occurred"), fmt.Errorf("%+v", errs)
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
	hfsts6, err := bootguard.GetHFSTS6(hw)
	if err != nil {
		return false, err, nil
	}
	valid, err := b.ValidateMEAgainstManifests(hfsts6)
	if !valid || err != nil {
		return false, fmt.Errorf("bootguard km/bpm doesn't match ME BootGuard configuration"), err
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

	hfsts6, err := bootguard.GetHFSTS6(hw)
	if err != nil {
		return false, fmt.Errorf("couldn't read HFSTS6: %v", err), nil
	}

	bgi, err := bootguard.GetBGInfo(hw)
	if err != nil {
		return false, err, nil
	}

	if p.Strict {
		valid, err := bootguard.StrictSaneBootGuardProvisioning(b.Version, hfsts6, bgi)
		if !valid || err != nil {
			return false, fmt.Errorf("provisiong boot guard configuraton in me isn't safe"), err
		}
	} else {
		valid, err := bootguard.SaneMEBootGuardProvisioning(b.Version, hfsts6, bgi)
		if !valid || err != nil {
			return false, fmt.Errorf("provisiong boot guard configuraton in me isn't safe"), err
		}
	}
	return true, nil, nil
}

// BootGuardTXT checks TXT requirements for safe BootGuard configuration
func BootGuardTXT(hw hwapi.LowLevelHardwareInterfaces, p *PreSet) (bool, error, error) {
	valid, err := bootguard.ValidTXTRegister(hw)
	if !valid || err != nil {
		return false, fmt.Errorf("txt regs aren't valid"), err
	}

	return true, nil, nil
}
