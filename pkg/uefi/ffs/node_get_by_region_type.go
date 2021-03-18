package ffs

import (
	fianoUEFI "github.com/linuxboot/fiano/pkg/uefi"
)

// GetByRegionType returns UEFI tree nodes of the requested flash region type.
func (node *Node) GetByRegionType(regionType fianoUEFI.FlashRegionType) (nodes []*Node, err error) {
	err = (&nodeVisitor{
		Callback: func(node Node) error {
			region, ok := node.Firmware.(fianoUEFI.Region)
			if !ok {
				// is not a region, skip
				return nil
			}

			if region.Type() != regionType {
				// is of wrong type
				return nil
			}
			nodes = append(nodes, &node)
			return nil
		},
	}).Run(node)
	return
}
