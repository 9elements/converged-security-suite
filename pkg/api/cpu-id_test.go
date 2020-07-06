package api

import (
	"testing"
)

func TestVersionString(t *testing.T) {

	txtAPI := GetApi()

	got := txtAPI.VersionString()

	if got == "" {
		t.Error("VersionString() returned the empty string.")
	}
}
