package pcr

import (
	"fmt"

	"github.com/9elements/converged-security-suite/v2/pkg/errors"
	"github.com/9elements/converged-security-suite/v2/pkg/intel/metadata/fit"
	"github.com/9elements/converged-security-suite/v2/pkg/registers"
)

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
