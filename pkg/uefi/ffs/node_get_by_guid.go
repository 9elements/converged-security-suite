package ffs

import (
	fianoGUID "github.com/linuxboot/fiano/pkg/guid"
)

// GetByGUID returns UEFI tree nodes with guid `guid`.
func (node *Node) GetByGUID(guid fianoGUID.GUID) (nodes []*Node, err error) {
	err = (&nodeVisitor{
		Callback: func(node Node) error {
			guidCmp := node.GUID()
			if guidCmp == nil || *guidCmp != guid {
				return nil
			}
			nodes = append(nodes, &node)
			return nil
		},
	}).Run(node)
	return
}
