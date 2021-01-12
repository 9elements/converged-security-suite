package cbnt

import (
	"bytes"
	"io/ioutil"
	"os"
	"testing"

	"github.com/9elements/converged-security-suite/v2/pkg/intel/metadata/manifest/bootpolicy"
	"github.com/9elements/converged-security-suite/v2/pkg/intel/metadata/manifest/key"
)

var (
	km  key.Manifest
	bpm bootpolicy.Manifest

	validCBnTOptions = &Options{
		KeyManifest:        &km,
		BootPolicyManifest: &bpm,
	}
)

const (
	validBIOSImage   = "test_artifacts/coreboot.rom"
	invalidBIOSImage = "test_artifacts/bare_coreboot.rom"

	filenotExistPath = "test_artifacts/fileNotExists.rom"

	validACM = "test_artifacts/ACM/valid_acm.bin"
	validBPM = "test_artifacts/BPM/valid_bpm.bin"
	validKM  = "test_artifacts/KM/valid_km.bin"

	invalidACM = "no such thing"
	invalidBPM = "test_artifacts/BPM/invalidBPM.bin"
	invalidKM  = "test_artifacts/KM/invalidkm.bin"

	validConfig     = "test_artifacts/Config/validConfig.json"
	invalidConfig   = "test_artifacts/Config/invalidConfig.json"
	writeConfigTest = "test_artifacts/Config/writeconfig.json"

	acmSize = 0x040000
	kmSize  = 0x000000
	bpmSize = 0x000000

	validRSALen2048    = 2048
	validRSALen3072    = 3072
	invalidRSALen0     = 0
	invalidRSALen1     = 1
	invalidRSALen4096  = 4096
	validECCCurve224   = 224
	validECCCurve256   = 256
	invalidECCCurve0   = 0
	invalidECCCurve1   = 1
	invalidECCCurve128 = 128
	invalidECCCurve384 = 384

	tmpPattern = "CBnTTests"

	testkey    = "test_artifacts/Keys/testkeybpm"
	testkeyPub = "test_artifats/Keys/testkey.pub"
	password   = ""
)

// 	ParseConfigValid takes a valid config file and parses it.

func TestParseConfigValid(t *testing.T) {
	_, err := ParseConfig(validConfig)
	if err != nil {
		t.Fatalf("Parse config file failed with error: %v", err)
	}
}

/*
	TestParseConfigInvalid takes a invalid config.
	A invalid config is defined by a field which holds a wrong type.
	There is no other way to get the json marshaller to error out.
*/
func TestParseConfigInvalid(t *testing.T) {
	_, err := ParseConfig(invalidConfig)
	if err == nil {
		t.Fatal("Invalid config got parsed")
	}
}

// TestWriteConfigValid writes a "valid" config to a temporary file.
func TestWriteConfigValid(t *testing.T) {
	tmpdir, err := ioutil.TempDir("", tmpPattern)
	if err != nil {
		t.Errorf("Creation of tmp dir failed: %v", err)
	}
	tmpfile, err := ioutil.TempFile(tmpdir, "")
	if err != nil {
		t.Errorf("Creation of tmp file failed: %v", err)
	}
	defer tmpfile.Close()
	defer cleanTmp(tmpdir, tmpfile)

	if err := WriteConfig(tmpfile, validCBnTOptions); err != nil {
		t.Fatalf("WriteConfig failed with error: %v", err)
	}
}

// TestReadConfigFromBIOSImageValid reads a CBnTOptions configuration from a BIOS file
func TestReadConfigFromBIOSImageValid(t *testing.T) {
	tmpdir, err := ioutil.TempDir("", tmpPattern)
	if err != nil {
		t.Errorf("Creation of tmp dir failed: %v", err)
	}
	tmpfile, err := ioutil.TempFile(tmpdir, "")
	if err != nil {
		t.Errorf("Creation of tmp file failed: %v", err)
	}
	defer tmpfile.Close()
	defer cleanTmp(tmpdir, tmpfile)

	_, err = ReadConfigFromBIOSImage(validBIOSImage, tmpfile)
	if err != nil {
		t.Fatalf("ReadConfigFromBIOSImage failed with error: %v", err)
	}

}

// 	TestReadConfigFromBIOSImageInvalidBIOSPath tries to read from a path
//  which does not exist.

func TestReadConfigFromBIOSImageInvalidBIOSPath(t *testing.T) {
	tmpdir, err := ioutil.TempDir("", tmpPattern)
	if err != nil {
		t.Errorf("Creation of tmp dir failed: %v", err)
	}
	tmpfile, err := ioutil.TempFile(tmpdir, "")
	if err != nil {
		t.Errorf("Creation of tmp file failed: %v", err)
	}
	defer tmpfile.Close()
	defer cleanTmp(tmpdir, tmpfile)

	_, err = ReadConfigFromBIOSImage(filenotExistPath, tmpfile)
	if err == nil {
		if err := os.Remove(writeConfigTest); err != nil {
			t.Logf("Deleting generated config file failed with error: %v", err)
		}
		t.Fatalf("ReadConfigFromBIOSImage succeeded where it should not")
	}
}

// TestReadConfigFromBIOSImageInvalidBIOSFile tries to read from a Coreboot image
// which has no Key Manifest and Bootpolicy Manifest.
func TestReadConfigFROMBIOSImageInvalidBIOSFile(t *testing.T) {
	tmpdir, err := ioutil.TempDir("", tmpPattern)
	if err != nil {
		t.Errorf("Creation of tmp dir failed: %v", err)
	}
	tmpfile, err := ioutil.TempFile(tmpdir, "")
	if err != nil {
		t.Errorf("Creation of tmp file failed: %v", err)
	}
	defer tmpfile.Close()
	defer cleanTmp(tmpdir, tmpfile)

	_, err = ReadConfigFromBIOSImage(invalidBIOSImage, tmpfile)
	if err == nil {
		if err := os.Remove(writeConfigTest); err != nil {
			t.Logf("Deleting generated config file failed with error: %v", err)
		}
		t.Fatal("TestReadConfigFromBIOSImageInvalid succeeded, but it should not")
	}

}

// The next eleven tests simply test the encryption/decryption keys generation
func TestGenRSAKeyValid2048(t *testing.T) {

	tmpKMpub, tmpKMpriv, tmpBPMpub, tmpBPMpriv, tmpdir, err := genTmpKeyFiles()
	if err != nil {
		t.Errorf("Creation of tmp files failed: %v", err)
	}
	defer tmpKMpub.Close()
	defer tmpKMpriv.Close()
	defer tmpBPMpub.Close()
	defer tmpBPMpriv.Close()
	defer cleanTmp(tmpdir, tmpKMpub, tmpKMpriv, tmpBPMpub, tmpBPMpriv)

	if err := GenRSAKey(validRSALen2048, password, tmpKMpub, tmpKMpriv, tmpBPMpub, tmpBPMpriv); err != nil {
		t.Fatalf("TestGenRSAKeyValid2048 failed with: %v", err)
	}

}

func TestGenRSAKeyValid2072(t *testing.T) {
	tmpKMpub, tmpKMpriv, tmpBPMpub, tmpBPMpriv, tmpdir, err := genTmpKeyFiles()
	if err != nil {
		t.Errorf("Creation of tmp files failed: %v", err)
	}
	defer tmpKMpub.Close()
	defer tmpKMpriv.Close()
	defer tmpBPMpub.Close()
	defer tmpBPMpriv.Close()
	defer cleanTmp(tmpdir, tmpKMpub, tmpKMpriv, tmpBPMpub, tmpBPMpriv)

	if err := GenRSAKey(validRSALen3072, password, tmpKMpub, tmpKMpriv, tmpBPMpub, tmpBPMpriv); err != nil {
		t.Fatalf("TestGenRSAKeyValid2084 failed with: %v", err)
	}

}

func TestGenRSAKeyInvalidLength0(t *testing.T) {
	tmpKMpub, tmpKMpriv, tmpBPMpub, tmpBPMpriv, tmpdir, err := genTmpKeyFiles()
	if err != nil {
		t.Errorf("Creation of tmp files failed: %v", err)
	}
	defer tmpKMpub.Close()
	defer tmpKMpriv.Close()
	defer tmpBPMpub.Close()
	defer tmpBPMpriv.Close()
	defer cleanTmp(tmpdir, tmpKMpub, tmpKMpriv, tmpBPMpub, tmpBPMpriv)

	if err := GenRSAKey(invalidRSALen0, password, tmpKMpub, tmpKMpriv, tmpBPMpub, tmpBPMpriv); err == nil {
		t.Fatalf("TestGenRSAKeyInvalidLength0 succeeded wrongly")
	}

}
func TestGenRSAKeyInvalidLength1(t *testing.T) {
	tmpKMpub, tmpKMpriv, tmpBPMpub, tmpBPMpriv, tmpdir, err := genTmpKeyFiles()
	if err != nil {
		t.Errorf("Creation of tmp files failed: %v", err)
	}
	defer tmpKMpub.Close()
	defer tmpKMpriv.Close()
	defer tmpBPMpub.Close()
	defer tmpBPMpriv.Close()
	defer cleanTmp(tmpdir, tmpKMpub, tmpKMpriv, tmpBPMpub, tmpBPMpriv)

	if err := GenRSAKey(invalidRSALen1, password, tmpKMpub, tmpKMpriv, tmpBPMpub, tmpBPMpriv); err == nil {
		t.Fatalf("TestGenRSAKeyInvalidLength1 failed with: %v", err)
	}

}

func TestGenRSAKeyInvalidLength4096(t *testing.T) {
	tmpKMpub, tmpKMpriv, tmpBPMpub, tmpBPMpriv, tmpdir, err := genTmpKeyFiles()
	if err != nil {
		t.Errorf("Creation of tmp files failed: %v", err)
	}
	defer tmpKMpub.Close()
	defer tmpKMpriv.Close()
	defer tmpBPMpub.Close()
	defer tmpBPMpriv.Close()
	defer cleanTmp(tmpdir, tmpKMpub, tmpKMpriv, tmpBPMpub, tmpBPMpriv)

	if err := GenRSAKey(invalidRSALen4096, password, tmpKMpub, tmpKMpriv, tmpBPMpub, tmpBPMpriv); err == nil {
		t.Fatalf("TestGenRSAKeyInvalidLength4096 failed with: %v", err)
	}

}

func TestGenECCKeyValid224(t *testing.T) {
	tmpKMpub, tmpKMpriv, tmpBPMpub, tmpBPMpriv, tmpdir, err := genTmpKeyFiles()
	if err != nil {
		t.Errorf("Creation of tmp files failed: %v", err)
	}
	defer tmpKMpub.Close()
	defer tmpKMpriv.Close()
	defer tmpBPMpub.Close()
	defer tmpBPMpriv.Close()
	defer cleanTmp(tmpdir, tmpKMpub, tmpKMpriv, tmpBPMpub, tmpBPMpriv)

	if err := GenECCKey(validECCCurve224, password, tmpKMpub, tmpKMpriv, tmpBPMpub, tmpBPMpriv); err != nil {
		t.Fatalf("TestGenECCKeyValid224 failed with: %v", err)
	}

}
func TestGenECCKeyValid256(t *testing.T) {
	tmpKMpub, tmpKMpriv, tmpBPMpub, tmpBPMpriv, tmpdir, err := genTmpKeyFiles()
	if err != nil {
		t.Errorf("Creation of tmp files failed: %v", err)
	}
	defer tmpKMpub.Close()
	defer tmpKMpriv.Close()
	defer tmpBPMpub.Close()
	defer tmpBPMpriv.Close()
	defer cleanTmp(tmpdir, tmpKMpub, tmpKMpriv, tmpBPMpub, tmpBPMpriv)

	if err := GenECCKey(validECCCurve256, password, tmpKMpub, tmpKMpriv, tmpBPMpub, tmpBPMpriv); err != nil {
		t.Fatalf("TestGenECCKeyValid256 failed with: %v", err)
	}

}

func TestGenECCKeyInvalidCurve0(t *testing.T) {
	tmpKMpub, tmpKMpriv, tmpBPMpub, tmpBPMpriv, tmpdir, err := genTmpKeyFiles()
	if err != nil {
		t.Errorf("Creation of tmp files failed: %v", err)
	}
	defer tmpKMpub.Close()
	defer tmpKMpriv.Close()
	defer tmpBPMpub.Close()
	defer tmpBPMpriv.Close()
	defer cleanTmp(tmpdir, tmpKMpub, tmpKMpriv, tmpBPMpub, tmpBPMpriv)

	if err := GenECCKey(invalidECCCurve0, password, tmpKMpub, tmpKMpriv, tmpBPMpub, tmpBPMpriv); err == nil {
		t.Fatalf("TestGenECCKeyInvalidCurve0 failed with: %v", err)
	}

}
func TestGenECCKeyInvalidCurve1(t *testing.T) {
	tmpKMpub, tmpKMpriv, tmpBPMpub, tmpBPMpriv, tmpdir, err := genTmpKeyFiles()
	if err != nil {
		t.Errorf("Creation of tmp files failed: %v", err)
	}
	defer tmpKMpub.Close()
	defer tmpKMpriv.Close()
	defer tmpBPMpub.Close()
	defer tmpBPMpriv.Close()
	defer cleanTmp(tmpdir, tmpKMpub, tmpKMpriv, tmpBPMpub, tmpBPMpriv)

	if err := GenECCKey(invalidECCCurve1, password, tmpKMpub, tmpKMpriv, tmpBPMpub, tmpBPMpriv); err == nil {
		t.Fatalf("TestGenECCKeyInvalidCurve1 failed with: %v", err)
	}

}
func TestGenECCKeyInvalidCurve128(t *testing.T) {
	tmpKMpub, tmpKMpriv, tmpBPMpub, tmpBPMpriv, tmpdir, err := genTmpKeyFiles()
	if err != nil {
		t.Errorf("Creation of tmp files failed: %v", err)
	}
	defer tmpKMpub.Close()
	defer tmpKMpriv.Close()
	defer tmpBPMpub.Close()
	defer tmpBPMpriv.Close()
	defer cleanTmp(tmpdir, tmpKMpub, tmpKMpriv, tmpBPMpub, tmpBPMpriv)

	if err := GenECCKey(invalidECCCurve128, password, tmpKMpub, tmpKMpriv, tmpBPMpub, tmpBPMpriv); err == nil {
		t.Fatalf("TestGenECCKeyInvalidCurve128 failed with: %v", err)
	}

}
func TestGenECCKeyInvalidCurve384(t *testing.T) {
	tmpKMpub, tmpKMpriv, tmpBPMpub, tmpBPMpriv, tmpdir, err := genTmpKeyFiles()
	if err != nil {
		t.Errorf("Creation of tmp files failed: %v", err)
	}
	defer tmpKMpub.Close()
	defer tmpKMpriv.Close()
	defer tmpBPMpub.Close()
	defer tmpBPMpriv.Close()
	defer cleanTmp(tmpdir, tmpKMpub, tmpKMpriv, tmpBPMpub, tmpBPMpriv)

	if err := GenECCKey(invalidECCCurve384, password, tmpKMpub, tmpKMpriv, tmpBPMpub, tmpBPMpriv); err == nil {
		t.Fatalf("TestGenECCKeyInvalidCurve384 failed with: %v", err)
	}

}

func TestDecryptPrivKeyValid(t *testing.T) {
	encKey, err := ioutil.ReadFile(testkey)
	if err != nil {
		t.Fatalf("TestDecryptPrivKeyValid failed with error: %v", err)
	}
	_, err = DecryptPrivKey(encKey, password)
	if err != nil {
		t.Fatalf("TestDecryptPrivKeyValid failed with error: %v", err)
	}
}

func TestWriteCBnTStructuresValid(t *testing.T) {
	data, err := ioutil.ReadFile(validBIOSImage)
	if err != nil {
		t.Fatalf("Failed to read validBIOSImage with error: %v", err)
	}
	tmpBPMfile, tmpKMfile, tmpACMfile, tmpdir, err := genTmpCBnTStrucFiles()
	if err != nil {
		t.Fatalf("Can't generate tmp filed: %v", err)
	}
	defer tmpBPMfile.Close()
	defer tmpKMfile.Close()
	defer tmpACMfile.Close()
	defer cleanTmp(tmpdir, tmpBPMfile, tmpKMfile, tmpACMfile)

	if err = WriteCBnTStructures(data, tmpBPMfile, tmpKMfile, tmpACMfile); err != nil {
		t.Fatalf("Failed to WriteCBnTStructures with error: %v", err)
	}

	bpmdata, err := ioutil.ReadFile(tmpBPMfile.Name())
	if err != nil {
		t.Errorf("Failed to read tpmBPM with: %v", err)
	}
	validBPMbin, err := ioutil.ReadFile(validBPM)
	if err != nil {
		t.Errorf("Failed to read validBPMpath with: %v", err)
	}
	if bytes.Equal(bpmdata, validBPMbin) != true {
		t.Fatalf("BPMs are not equal but they should")
	}

	kmdata, err := ioutil.ReadFile(tmpKMfile.Name())
	if err != nil {
		t.Errorf("Failed to read tmpKM with: %v", err)
	}
	validKMbin, err := ioutil.ReadFile(validKM)
	if err != nil {
		t.Errorf("Failed to read validKMpath with error: %v", err)
	}
	if bytes.Equal(kmdata, validKMbin) != true {
		t.Fatalf("KMs are not equla but they should")
	}

	acmdata, err := ioutil.ReadFile(tmpACMfile.Name())
	if err != nil {
		t.Errorf("Failed to read tmpACM with error: %v", err)
	}
	validacmbin, err := ioutil.ReadFile(validACM)
	if err != nil {
		t.Errorf("Failed to read validACMpath with error: %v", err)
	}
	if bytes.Equal(acmdata, validacmbin) != true {
		t.Fatalf("ACMs are not the same, but they should.")
	}

}

func TestWriteCBnTStructuresInvalidBIOSImage(t *testing.T) {
	data, err := ioutil.ReadFile(invalidBIOSImage)
	if err != nil {
		t.Fatalf("Failed to read invalidBIOSImage with error: %v", err)
	}

	tmpBPMfile, tmpKMfile, tmpACMfile, tmpdir, err := genTmpCBnTStrucFiles()
	if err != nil {
		t.Fatalf("Can't generate tmp filed: %v", err)
	}
	defer tmpBPMfile.Close()
	defer tmpKMfile.Close()
	defer tmpACMfile.Close()
	defer cleanTmp(tmpdir, tmpBPMfile, tmpKMfile, tmpACMfile)

	if err = WriteCBnTStructures(data, tmpBPMfile, tmpKMfile, tmpACMfile); err == nil {
		t.Fatalf("WriteCBnTStructures succeeded but it should not.")
	}
}

func TestParseFITEntriesValid(t *testing.T) {
	data, err := ioutil.ReadFile(validBIOSImage)
	if err != nil {
		t.Errorf("Can't read valid BIOS image with error: %v", err)
	}
	bpm, km, acm, err := ParseFITEntries(data)
	if err != nil {
		t.Fatalf("ParseFITEntries failed with error: %v", err)
	}

	validBPM, err := ioutil.ReadFile(validBPM)
	if err != nil {
		t.Errorf("Failed to read validBPMpath with: %v", err)
	}
	if bytes.Equal(bpm.DataBytes, validBPM) != true {
		t.Fatalf("BPMs are not equal but they should")
	}

	validKM, err := ioutil.ReadFile(validKM)
	if err != nil {
		t.Errorf("Failed to read validKMpath with error: %v", err)
	}
	if bytes.Equal(km.DataBytes, validKM) != true {
		t.Fatalf("KMs are not equla but they should")
	}

	validacm, err := ioutil.ReadFile(validACM)
	if err != nil {
		t.Errorf("Failed to read validACMpath with error: %v", err)
	}
	if bytes.Equal(acm.DataBytes, validacm) != true {
		t.Fatalf("ACMs are not the same, but they should.")
	}
}

func TestParseFITEntriesInvalidBIOSImage(t *testing.T) {
	data, err := ioutil.ReadFile(invalidBIOSImage)
	if err != nil {
		t.Errorf("Can't read valid BIOS image with error: %v", err)
	}
	_, _, _, err = ParseFITEntries(data)
	if err == nil {
		t.Fatalf("ParseFITEntries succeeded, but it should not")
	}
}

func TestStitchFITEntriesValid(t *testing.T) {
	acm, err := ioutil.ReadFile(validACM)
	if err != nil {
		t.Errorf("Read acm failed: %v", err)
	}
	bpm, err := ioutil.ReadFile(validBPM)
	if err != nil {
		t.Errorf("Read BPM failed: %v", err)
	}
	km, err := ioutil.ReadFile(validKM)
	if err != nil {
		t.Errorf("Read KM failed: %v", err)
	}
	if err := StitchFITEntries(validBIOSImage, acm, bpm, km); err != nil {
		t.Errorf("Stitching failed with error: %v", err)
	}
}

func TestStitchFITEntriesInvalidBIOSPath(t *testing.T) {
	acm, err := ioutil.ReadFile(validACM)
	if err != nil {
		t.Errorf("Read acm failed: %v", err)
	}
	bpm, err := ioutil.ReadFile(validBPM)
	if err != nil {
		t.Errorf("Read BPM failed: %v", err)
	}
	km, err := ioutil.ReadFile(validKM)
	if err != nil {
		t.Errorf("Read KM failed: %v", err)
	}
	if err := StitchFITEntries(filenotExistPath, acm, bpm, km); err == nil {
		t.Errorf("Stitching succeeded, but it shouldn't")
	}
}

func TestParseKMValid(t *testing.T) {
	kmbin, err := ioutil.ReadFile(validKM)
	if err != nil {
		t.Errorf("Error reading KM: %v", err)
	}
	r := bytes.NewReader(kmbin)
	_, err = ParseKM(r)
	if err != nil {
		t.Errorf("Setting up reader for KM failed: %v", err)
	}
	// Compare result to valid KM
}

func TestParseBPMValid(t *testing.T) {
	bpmbin, err := ioutil.ReadFile(validBPM)
	if err != nil {
		t.Errorf("Error reading KM: %v", err)
	}
	r := bytes.NewReader(bpmbin)
	_, err = ParseBPM(r)
	if err != nil {
		t.Errorf("Parsing BPM succeeded, but it shouldn't")
	}
	// Compare result to valid BPM
}

func genTmpKeyFiles() (*os.File, *os.File, *os.File, *os.File, string, error) {
	tmpdir, err := ioutil.TempDir("", "CBnTTests")
	if err != nil {
		return nil, nil, nil, nil, "", err
	}
	tmpKMpub, err := ioutil.TempFile(tmpdir, "")
	if err != nil {
		return nil, nil, nil, nil, "", err
	}
	tmpKMpriv, err := ioutil.TempFile(tmpdir, "")
	if err != nil {
		return nil, nil, nil, nil, "", err
	}
	tmpBPMpub, err := ioutil.TempFile(tmpdir, "")
	if err != nil {
		return nil, nil, nil, nil, "", err
	}
	tmpBPMpriv, err := ioutil.TempFile(tmpdir, "")
	if err != nil {
		return nil, nil, nil, nil, "", err
	}
	return tmpKMpub, tmpKMpriv, tmpBPMpub, tmpBPMpriv, tmpdir, nil

}

func genTmpCBnTStrucFiles() (*os.File, *os.File, *os.File, string, error) {
	tmpdir, err := ioutil.TempDir("", "CBnTTests")
	if err != nil {
		return nil, nil, nil, "", err
	}
	tmpKMfile, err := ioutil.TempFile(tmpdir, "")
	if err != nil {
		return nil, nil, nil, "", err
	}
	tmpBPMfile, err := ioutil.TempFile(tmpdir, "")
	if err != nil {
		return nil, nil, nil, "", err
	}
	tmpACMfile, err := ioutil.TempFile(tmpdir, "")
	if err != nil {
		return nil, nil, nil, "", err
	}
	return tmpKMfile, tmpBPMfile, tmpACMfile, tmpdir, nil
}

func cleanTmp(dir string, files ...*os.File) error {
	for _, item := range files {
		if err := os.Remove(item.Name()); err != nil {
			return err
		}
	}
	if err := os.Remove(dir); err != nil {
		return err
	}
	return nil
}

func getFileSize(file *os.File) int64 {
	filestat, _ := file.Stat()
	return filestat.Size()
}
