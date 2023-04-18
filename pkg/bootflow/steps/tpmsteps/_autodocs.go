//go:build none
// +build none

package tpmsteps

// This files is used only to provide hints to the "goplantuml" tool

type MeasureSeparator struct {
	types.StaticStep
	tpmactions.TPMEvent
	datasources.StaticData
}

type MeasureUEFIGUIDFirst struct {
	types.StaticStep
	tpmactions.TPMEvent
	datasources.UEFIGUIDFirst
}
