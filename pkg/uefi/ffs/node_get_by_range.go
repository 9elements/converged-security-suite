package ffs

import (
	pkgbytes "github.com/9elements/converged-security-suite/v2/pkg/bytes"
)

// GetByRange returns nodes which overlaps the range `byteRange`.
func (node *Node) GetByRange(byteRange pkgbytes.Range) (nodes []*Node, err error) {
	err = (&nodeVisitor{
		Callback: func(node Node) error {
			if !node.Intersect(byteRange) {
				return nil
			}
			nodes = append(nodes, &node)
			return nil
		},
	}).Run(node)
	return
}

// GetNamesByRange returns known names of volumes which intersects
// with the selected byte range.
//
// Since there's no reliable enough way to get volume offsets, we
// introduce this function to be able to extract at least names
// in a little-bit more reliable manner.
//
// This function should be deprecated after issue
// https://github.com/linuxboot/fiano/issues/164
// will be closed.
func (node *Node) GetNamesByRange(byteRange pkgbytes.Range) []string {
	var result []string
	rangeMap := node.NameToRangesMap()
	for name, ranges := range rangeMap {
		for _, r := range ranges {
			if r.Intersect(byteRange) {
				result = append(result, name)
			}
		}
	}
	return result
}
