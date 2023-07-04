package ffs

import (
	fianoUEFI "github.com/linuxboot/fiano/pkg/uefi"
)

// GetByRegionType returns UEFI tree nodes of the requested flash region type.
func (node *Node) GetByRegionType(regionType fianoUEFI.FlashRegionType) (nodes []*Node, err error) {
	err = (&NodeVisitor{
		Callback: func(node Node) (bool, error) {
			region, ok := node.Firmware.(fianoUEFI.Region)
			if !ok {
				// is not a region, skip
				return true, nil
			}

			if region.Type() != regionType {
				// is of wrong type
				return true, nil
			}
			nodes = append(nodes, &node)
			return true, nil
		},
	}).Run(node)
	return
}
