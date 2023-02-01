package intelbiosimage

import (
	"github.com/9elements/converged-security-suite/v2/pkg/bootflow/systemartifacts/biosimage/accessor"
	"github.com/linuxboot/fiano/pkg/intel/metadata/fit"
)

// FIT returns the Intel Firmware Interface Table.
func (a *Accessor) FIT() (fit.Entries, error) {
	result := accessor.Memoize(a.Cache, func() (result struct {
		entries fit.Entries
		err     error
	}) {
		result.entries, result.err = fit.GetEntries(a.Image.Content)
		return
	})
	return result.entries, result.err
}
