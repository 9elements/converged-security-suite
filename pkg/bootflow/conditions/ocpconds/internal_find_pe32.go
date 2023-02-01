package ocpconds

import (
	"github.com/linuxboot/fiano/pkg/uefi"
)

type visitorFindPE32 struct {
	Found *uefi.Section
}

var _ uefi.Visitor = (*visitorFindPE32)(nil)

func (visitorFindPE32) Run(uefi.Firmware) error {
	return nil
}
func (v *visitorFindPE32) Visit(fw uefi.Firmware) error {
	if section, ok := fw.(*uefi.Section); ok {
		if section.Header.Type == uefi.SectionTypePE32 {
			v.Found = section
			return nil
		}
	}
	return fw.ApplyChildren(v)
}
