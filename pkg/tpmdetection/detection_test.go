package tpmdetection

import (
	"fmt"
	"io/ioutil"
	"os"
	"path"
	"testing"
)

func TestTPMDetection(t *testing.T) {
	t.Run("no_tpm_device", func(t *testing.T) {
		d, err := ioutil.TempDir("", "tpm_detection")
		if err != nil {
			t.Errorf("failed to create temp director: %vy", err)
			t.Skip()
		}
		defer func() {
			_ = os.RemoveAll(d)
		}()
		localTPM, err := local(path.Join(d, "device"), path.Join(d, "capabilities"))
		if err != nil {
			t.Errorf("failed to detect TPM version, err: %v", err)
			t.Skip()
		}
		if localTPM != TypeNoTPM {
			t.Errorf("Expetcted %v, but got: %v", TypeNoTPM, localTPM)
		}
	})

	d, err := ioutil.TempDir("", "tpm_detection")
	if err != nil {
		t.Errorf("failed to create temp director: %vy", err)
		t.Skip()
	}
	defer func() {
		_ = os.RemoveAll(d)
	}()
	devicePath := path.Join(d, "device")
	f, err := os.Create(devicePath)
	if err != nil {
		t.Errorf("Failed to create local file: %s, err: %v", devicePath, err)
		t.Skip()
	}
	_ = f.Close()
	capabilitiesPath := path.Join(d, "capabilities")

	t.Run("no_capabilities", func(t *testing.T) {
		localTPM, err := local(devicePath, path.Join(d, "sub", "capabilities"))
		if err != nil {
			t.Errorf("failed to detect TPM version, err: %v", err)
			t.Skip()
		}
		if localTPM != TypeTPM20 {
			t.Errorf("Expetcted %v, but got: %v", TypeTPM20, localTPM)
		}
	})

	testTPMDetectionByCapabilities := func(t *testing.T, capTPMVersion string, expected Type) {
		f, err := os.Create(capabilitiesPath)
		if err != nil {
			t.Errorf("Failed to create local file: %s, err: %v", devicePath, err)
			t.Skip()
		}
		_, err = f.WriteString(fmt.Sprintf("TCG version: %s", capTPMVersion))
		_ = f.Close()
		defer func() {
			err := os.Remove(capabilitiesPath)
			if err != nil {
				t.Errorf("failed to remove capabilities file, err: %v", err)
			}
		}()

		localTPM, err := local(devicePath, capabilitiesPath)
		if err != nil {
			t.Errorf("failed to detect TPM version, err: %v", err)
			t.Skip()
		}
		if localTPM != expected {
			t.Errorf("Expetcted %v, but got: %v", expected, localTPM)
		}
	}

	t.Run("capabilities_20", func(t *testing.T) {
		testTPMDetectionByCapabilities(t, "2.0", TypeTPM20)
	})
	t.Run("capabilities_20", func(t *testing.T) {
		testTPMDetectionByCapabilities(t, "1.2", TypeTPM12)
	})
}
