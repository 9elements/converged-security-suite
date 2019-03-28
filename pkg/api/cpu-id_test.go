package api

import (
	"testing"
)

func TestVersionString(t *testing.T) {
	got := VersionString()

	if got == "" {
		t.Error("VersionString() returned the empty string.")
	}
}
