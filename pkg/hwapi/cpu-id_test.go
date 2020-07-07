package hwapi

import (
	"testing"
)

func TestVersionString(t *testing.T) {

	txtAPI := GetAPI()

	got := txtAPI.VersionString()

	if got == "" {
		t.Error("VersionString() returned the empty string.")
	}
}
