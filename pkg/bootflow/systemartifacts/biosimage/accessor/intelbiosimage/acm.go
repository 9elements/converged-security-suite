package intelbiosimage

import (
	"fmt"

	"github.com/9elements/converged-security-suite/v2/pkg/bootflow/systemartifacts/biosimage/accessor"
	"github.com/linuxboot/fiano/pkg/intel/metadata/fit"
)

func (a *Accessor) ACM() (
	data *fit.EntrySACMData,
	entry *fit.EntrySACM,
	err error,
) {
	result := accessor.Memoize(a.Cache, func() (result struct {
		data  *fit.EntrySACMData
		entry *fit.EntrySACM
		err   error
	}) {
		fitEntries, err := a.FIT()
		if err != nil {
			result.err = fmt.Errorf("unable to get FIT entries: %w", err)
			return
		}

		for _, fitEntry := range fitEntries {
			switch fitEntry := fitEntry.(type) {
			case *fit.EntrySACM:
				acmData, err := fitEntry.ParseData()
				if err != nil {
					result.err = fmt.Errorf("failed to parse ACM, err: %v", err)
					return
				}
				result.data = acmData
				result.entry = fitEntry
				return
			}
		}

		result.err = fmt.Errorf("ACM FIT entry is not found")
		return
	})

	return result.data, result.entry, result.err
}
