package ffs

import (
	fianoGUID "github.com/linuxboot/fiano/pkg/guid"
)

// GetByGUID returns UEFI tree nodes with guid `guid`.
func (node *Node) GetByGUID(guid fianoGUID.GUID) (nodes []*Node, err error) {
	err = (&NodeVisitor{
		Callback: func(node Node) (bool, error) {
			guidCmp := node.GUID()
			if guidCmp == nil || *guidCmp != guid {
				return true, nil
			}
			nodes = append(nodes, &node)
			return true, nil
		},
	}).Run(node)
	return
}
