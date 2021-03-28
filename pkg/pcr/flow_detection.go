package pcr

import (
	"bytes"
	"fmt"
	"github.com/9elements/converged-security-suite/v2/pkg/intel/metadata/manifest"

	"github.com/9elements/converged-security-suite/v2/pkg/errors"
	"github.com/9elements/converged-security-suite/v2/pkg/intel/metadata/fit"
	"github.com/9elements/converged-security-suite/v2/pkg/registers"
)

func DetectTPM(firmware Firmware, regs registers.Registers) (registers.TPMType, error) {
	// We have two approaches:
	// - based on registers provides a reliable results, but these values may not exist
	// - based on firmware may provide hints that TPM2.0 is not supported
	btgACMInfo, found := registers.FindBTGSACMInfo(regs)
	if found {
		return btgACMInfo.TPMType(), nil
	}

	acmPolicyStatus, found := registers.FindACMPolicyStatus(regs)
	if found {
		return acmPolicyStatus.TPMType(), nil
	}

	if firmware != nil {
		fitEntries, err := fit.GetEntries(firmware.Buf())
		if err != nil {
			return 0, fmt.Errorf("unable to parse FIT entries: %w", err)
		}

		for _, entry := range fitEntries {
			switch fitEntry := entry.(type) {
			case *fit.EntrySACM:
				data, err := fitEntry.ParseData()
				if data == nil {
					return 0, fmt.Errorf("unable to parse EntrySACM: %w", err)
				}
				_, chipset, err := manifest.ParseChipsetACModuleInformation(bytes.NewBuffer(data.UserArea))
				if err != nil {
					return 0, fmt.Errorf("failed to read ChipsetACModuleInformation, err: %w", err)
				}

				// From Intel TXT Software Development Guide:
				// Version 5 included all
				// changes added to support TPM 2.0 family.
				if chipset.Base.Version < 5 {
					return registers.TPMType12, nil
				}

				// chipset.TPMInfoList is an offset in bytes from ACM start.
				image := firmware.ImageBytes()
				var tpmInfo manifest.TPMInfoList
				_, err = tpmInfo.ReadFrom(bytes.NewBuffer(image[fitEntry.GetDataOffset()+uint64(chipset.TPMInfoList):]))
				if err != nil {
					return 0, fmt.Errorf("failed to read TPMInfoList, err: %w", err)
				}

				bool2Int := func(b bool) int {
					if b {
						return 1
					}
					return 0
				}
				tpmFamilySupport := tpmInfo.Capabilities.TPMFamilySupport()
				// if none options is set - no TPM
				// if only one option is set - can determine
				s := bool2Int(tpmFamilySupport.IsDiscreteTPM20Supported()) +
					bool2Int(tpmFamilySupport.IsFirmwareTPM20Supported()) +
					bool2Int(tpmFamilySupport.IsDiscreteTPM12Supported())

				if s == 0 {
					return registers.TPMTypeNoTpm, nil
				}
				if s == 1 {
					switch {
					case tpmFamilySupport.IsDiscreteTPM12Supported():
						return registers.TPMType12, nil
					case tpmFamilySupport.IsDiscreteTPM20Supported():
						return registers.TPMType20, nil
					case tpmFamilySupport.IsFirmwareTPM20Supported():
						return registers.TPMTypeIntelPTT, nil
					}
				}
			}
		}
	}

	return 0, fmt.Errorf("unable to detect TPM type")
}

func DetectAttestationFlow(firmware Firmware, regs registers.Registers) (Flow, error) {
	fitEntries, err := fit.GetEntries(firmware.Buf())
	if err != nil {
		return FlowAuto, fmt.Errorf("unable to parse FIT entries: %w", err)
	}

	isCBnT, err := isCBnT(fitEntries)
	if err == nil && isCBnT {
		// TODO: check that it is 0T using registers
		return FlowIntelCBnT0T, nil
	}
	isTXTEnabledValue, err := isTXTEnabled(fitEntries)
	if err != nil {
		return FlowAuto, err
	}
	if isTXTEnabledValue {
		tpmType, err := DetectTPM(firmware, regs)
		if err != nil && tpmType == registers.TPMType12 {
			return FlowIntelLegacyTXTEnabledTPM12, nil
		}
		return FlowIntelLegacyTXTEnabled, nil
	}
	return FlowIntelLegacyTXTDisabled, nil
}

func isTXTEnabled(fitEntries []fit.Entry) (bool, error) {
	for _, fitEntry := range fitEntries {
		switch fitEntry := fitEntry.(type) {
		case *fit.EntryTXTPolicyRecord:
			data, err := fitEntry.Parse()
			if data == nil {
				return false, fmt.Errorf("unable to parse TXT policy record: %w", err)
			}
			return data.IsTXTEnabled(), errors.MultiError(fitEntry.HeadersErrors).ReturnValue()
		}
	}

	return false, &ErrNoTXTPolicyRecord{}
}

// isCBnT checks if firmware supports CBnT
// There is no formal flag that points to CBnT, but CBnT:
// - must have KeyManifest and BootPolicyManifest
// - introduced changes to KeyManifest: structure version is updated to 2.1
func isCBnT(fitEntries []fit.Entry) (bool, error) {
	var bootPolicyFound bool
	var keyManifestFound bool

	for _, fitEntry := range fitEntries {
		switch fitEntry := fitEntry.(type) {
		case *fit.EntryKeyManifestRecord:
			data, err := fitEntry.ParseData()
			if data == nil {
				return false, fmt.Errorf("unable to parse KeyManifest policy record: %w", err)
			}
			if data.Version < 0x21 {
				return false, nil
			}
			keyManifestFound = true
		case *fit.EntryBootPolicyManifestRecord:
			bootPolicyFound = true
		}
	}

	return bootPolicyFound && keyManifestFound, nil
}
