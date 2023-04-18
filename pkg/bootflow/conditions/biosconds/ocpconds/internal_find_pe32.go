package ocpconds

import (
	"github.com/linuxboot/fiano/pkg/uefi"
)

type visitorFindPE32orTE struct {
	Found *uefi.Section
}

var _ uefi.Visitor = (*visitorFindPE32orTE)(nil)

func (v *visitorFindPE32orTE) Run(fw uefi.Firmware) error {
	return v.Visit(fw)
}
func (v *visitorFindPE32orTE) Visit(fw uefi.Firmware) error {
	if section, ok := fw.(*uefi.Section); ok {
		switch section.Header.Type {
		case uefi.SectionTypePE32, uefi.SectionTypeTE:
			v.Found = section
			return nil
		}
	}
	return fw.ApplyChildren(v)
}
