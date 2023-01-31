package intelbiosimage

import (
	"fmt"

	"github.com/9elements/converged-security-suite/v2/pkg/bootflow/systemartifacts/biosimage/accessor"
	"github.com/linuxboot/fiano/pkg/intel/metadata/fit"
	"github.com/linuxboot/fiano/pkg/intel/metadata/manifest/bootpolicy"
)

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
				bpManifest, err := fitEntry.ParseData()
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
