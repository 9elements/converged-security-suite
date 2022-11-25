//go:build none
// +build none

package types

// This files is used only to provide hints to the "goplantuml" tool

type State struct {
	SystemArtifacts
	TrustChains
	Flow
	MeasuredData
}

type Data struct {
	References
	pkgbytes.Ranges
}

type Reference struct {
	SystemArtifact
}

type MeasuredData struct {
	Data Data
	TrustChain
}
