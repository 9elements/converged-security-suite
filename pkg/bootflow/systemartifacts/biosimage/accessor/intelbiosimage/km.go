package intelbiosimage

import (
	"fmt"

	"github.com/9elements/converged-security-suite/v2/pkg/bootflow/systemartifacts/biosimage/accessor"
	key "github.com/linuxboot/fiano/pkg/intel/metadata/cbnt/cbntkey"
	"github.com/linuxboot/fiano/pkg/intel/metadata/fit"
)

func (a *Accessor) KeyManifest() (
	data *key.Manifest,
	entry *fit.EntryKeyManifestRecord,
	err error,
) {
	result := accessor.Memoize(a.Cache, func() (result struct {
		data  *key.Manifest
		entry *fit.EntryKeyManifestRecord
		err   error
	}) {
		fitEntries, err := a.FIT()
		if err != nil {
			result.err = fmt.Errorf("unable to get FIT entries: %w", err)
			return
		}

		for _, fitEntry := range fitEntries {
			switch fitEntry := fitEntry.(type) {
			case *fit.EntryKeyManifestRecord:
				_, keyManifest, err := fitEntry.ParseData()
				if err != nil {
					result.err = err
					return
				}
				result.data, result.entry = keyManifest, fitEntry
				return
			}
		}

		result.err = fmt.Errorf("key manifest FIT entry is not found")
		return
	})

	return result.data, result.entry, result.err
}
