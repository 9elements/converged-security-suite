package api

import (
	"testing"
)

func TestExtractFit(t *testing.T) {

	_, err := ExtractFit("/home/riot/work_stuff/coreboot_wege100s_systemboot_tboot.rom")
	if err != nil {
		t.Errorf("ExtractFit() failed: %v", err)
	}

}
