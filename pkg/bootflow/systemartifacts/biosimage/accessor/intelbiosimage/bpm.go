package intelbiosimage

import (
	"fmt"

	"github.com/9elements/converged-security-suite/v2/pkg/bootflow/systemartifacts/biosimage/accessor"
	bootpolicy "github.com/linuxboot/fiano/pkg/intel/metadata/cbnt/cbntbootpolicy"
	"github.com/linuxboot/fiano/pkg/intel/metadata/fit"
)

// BootPolicyManifest returns the Boot Policy Manifest.
func (a *Accessor) BootPolicyManifest() (
	data *bootpolicy.Manifest,
	entry *fit.EntryBootPolicyManifestRecord,
	err error,
) {
	result := accessor.Memoize(a.Cache, func() (result struct {
		data  *bootpolicy.Manifest
		entry *fit.EntryBootPolicyManifestRecord
		err   error
	}) {
		fitEntries, err := a.FIT()
		if err != nil {
			result.err = fmt.Errorf("unable to get FIT entries: %w", err)
			return
		}

		for _, fitEntry := range fitEntries {
			switch fitEntry := fitEntry.(type) {
			case *fit.EntryBootPolicyManifestRecord:
				_, bpManifest, err := fitEntry.ParseData()
				if err != nil {
					result.err = err
					return
				}
				result.data, result.entry = bpManifest, fitEntry
				return
			}
		}

		result.err = fmt.Errorf("boot policy manifest FIT entry is not found")
		return
	})

	return result.data, result.entry, result.err
}
