package ocpconds

import (
	"github.com/linuxboot/fiano/pkg/uefi"
)

type visitorFindPE32orTE struct {
	Found *uefi.Section
}

var _ uefi.Visitor = (*visitorFindPE32orTE)(nil)

func (visitorFindPE32orTE) Run(uefi.Firmware) error {
	return nil
}
func (v *visitorFindPE32orTE) Visit(fw uefi.Firmware) error {
	if section, ok := fw.(*uefi.Section); ok {
		switch section.Header.Type {
		case uefi.SectionTypePE32:
		case uefi.SectionTypeTE:
			v.Found = section
			return nil
		}
	}
	return fw.ApplyChildren(v)
}
