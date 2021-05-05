package pcr

import (
	"bytes"
	"fmt"

	"github.com/9elements/converged-security-suite/v2/pkg/intel/metadata/manifest"
	"github.com/9elements/converged-security-suite/v2/pkg/tpmdetection"

	"github.com/9elements/converged-security-suite/v2/pkg/errors"
	"github.com/9elements/converged-security-suite/v2/pkg/intel/metadata/fit"
	"github.com/9elements/converged-security-suite/v2/pkg/registers"
)

func DetectTPM(firmware Firmware, regs registers.Registers) (tpmdetection.Type, error) {
	// We have two approaches:
	// - based on registers provides a reliable results, but these values may not exist
	// - based on firmware may provide hints that TPM2.0 is not supported

	convert := func(tpmType registers.TPMType) (tpmdetection.Type, error) {
		switch tpmType {
		case registers.TPMTypeNoTpm:
			return tpmdetection.TypeNoTPM, nil
		case registers.TPMType12:
			return tpmdetection.TypeTPM12, nil
		case registers.TPMType20, registers.TPMTypeIntelPTT:
			return tpmdetection.TypeTPM20, nil
		}
		return tpmdetection.TypeNoTPM, fmt.Errorf("unknown registers TPM type: %d", tpmType)
	}

	btgACMInfo, found := registers.FindBTGSACMInfo(regs)
	if found {
		return convert(btgACMInfo.TPMType())
	}

	acmPolicyStatus, found := registers.FindACMPolicyStatus(regs)
	if found {
		return convert(acmPolicyStatus.TPMType())
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
					return tpmdetection.TypeTPM12, nil
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
					return tpmdetection.TypeNoTPM, nil
				}
				if s == 1 {
					switch {
					case tpmFamilySupport.IsDiscreteTPM12Supported():
						return tpmdetection.TypeTPM12, nil
					case tpmFamilySupport.IsDiscreteTPM20Supported():
						return tpmdetection.TypeTPM20, nil
					case tpmFamilySupport.IsFirmwareTPM20Supported():
						return tpmdetection.TypeTPM20, nil
					}
				}
			}
		}
	}

	return 0, fmt.Errorf("unable to detect TPM type")
}

// DetectMainAttestationFlow returns the PCR0 measurements flow assuming
// no validation errors occurred.
func DetectMainAttestationFlow(firmware Firmware, regs registers.Registers, tpmDevice tpmdetection.Type) (Flow, error) {
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
		switch tpmDevice {
		case tpmdetection.TypeTPM12:
			return FlowIntelLegacyTXTEnabledTPM12, nil
		case tpmdetection.TypeTPM20:
			return FlowIntelLegacyTXTEnabled, nil
		case tpmdetection.TypeNoTPM:
		default:
			return FlowAuto, fmt.Errorf("unexpected tpm device value: %d", tpmDevice)
		}

		// try to detect based on registers/firmware
		detectedTPM, err := DetectTPM(firmware, regs)
		if err != nil && detectedTPM == tpmdetection.TypeTPM12 {
			return FlowIntelLegacyTXTEnabledTPM12, nil
		}
		// TPM2.0 is more likely
		return FlowIntelLegacyTXTEnabled, nil
	}
	return FlowIntelLegacyTXTDisabled, nil
}

// DetectAttestationFlow return the PCR0 measurements flow.
//
// For example CBnT-0T falls back to TXT-disabled if BPM signature is invalid.
func DetectAttestationFlow(firmware Firmware, regs registers.Registers, tpmDevice tpmdetection.Type) (Flow, error) {
	flow, err := DetectMainAttestationFlow(firmware, regs, tpmDevice)
	if err != nil {
		return flow, err
	}

	switch flow {
	case FlowIntelCBnT0T, FlowIntelLegacyTXTEnabled, FlowIntelLegacyTXTEnabledTPM12:
		err := flow.ValidateFlow().Validate(firmware)
		if err != nil {
			return FlowIntelLegacyTXTDisabled, fmt.Errorf("TXT disabled: %w", err)
		}
	}

	return flow, nil
}

func isTXTEnabled(fitEntries []fit.Entry) (bool, error) {
	for _, fitEntry := range fitEntries {
		switch fitEntry := fitEntry.(type) {
		case *fit.EntryTXTPolicyRecord:
			data, err := fitEntry.Parse()
			if data == nil {
				return false, fmt.Errorf("unable to parse TXT policy record: %w", err)
			}
			switch s := data.(type) {
			case fit.EntryTXTPolicyRecordDataFlatPointer:
				// Document #599500 says:
				// > if this structure is not present or is invalid,
				// > the Startup ACM will behave, as if TXT Config Policy = 1
				if s.TPMPolicyPointer() >= 4<<30 {
					// Document #599500 says:
					// > The memory address should be under 4 GB.
					return true, nil
				}
				if fitEntry.EntryBase.Headers.IsChecksumValid() || fitEntry.EntryBase.Headers.Type() != 0 {
					// Document #599500 says:
					// > The C_V bit in this entry should be cleared to 0
					return true, nil
				}

				return data.IsTXTEnabled(), errors.MultiError(fitEntry.HeadersErrors).ReturnValue()
			default:
				return true, fmt.Errorf("struct type %T is not supported, yet", s)
			}
		}
	}

	// Document #599500 says:
	// > If there are zero records of this type Intel® TXT state defaults to be in
	// > ENABLED state.
	return true, nil
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
