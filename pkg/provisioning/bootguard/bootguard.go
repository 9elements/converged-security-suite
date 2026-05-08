package bootguard

import (
	"bytes"
	"crypto"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"

	"github.com/9elements/converged-security-suite/v2/pkg/tools"
	"github.com/9elements/converged-security-suite/v2/pkg/uefi/consts"
	"github.com/linuxboot/fiano/pkg/cbfs"

	"github.com/linuxboot/fiano/pkg/intel/metadata/cbnt"
	bootpolicy "github.com/linuxboot/fiano/pkg/intel/metadata/cbnt/bootpolicy"
	keymanifest "github.com/linuxboot/fiano/pkg/intel/metadata/cbnt/keymanifest"
	"github.com/linuxboot/fiano/pkg/intel/metadata/fit"
	"github.com/linuxboot/fiano/pkg/uefi"
	"github.com/tidwall/pretty"

	log "github.com/sirupsen/logrus"
)

// Everything more secure than SHA-1
const minHashTypeSize = 32

func bpmReader(bpm bootpolicy.Manifest) (*bytes.Reader, error) {
	if bpm == nil {
		return nil, fmt.Errorf("manifest is nil")
	}
	buf := new(bytes.Buffer)
	_, err := bpm.WriteTo(buf)
	if err != nil {
		return nil, err
	}
	return bytes.NewReader(buf.Bytes()), nil
}

func kmReader(km keymanifest.Manifest) (*bytes.Reader, error) {
	if km == nil {
		return nil, fmt.Errorf("manifest is nil")
	}
	buf := new(bytes.Buffer)
	_, err := km.WriteTo(buf)
	if err != nil {
		return nil, err
	}
	return bytes.NewReader(buf.Bytes()), nil
}

func NewVData(vdata VersionedData) (*BootGuard, error) {
	var b BootGuard

	if vdata.BGbpm != nil && vdata.BGkm != nil {
		// For BG 1.0 KM and BPM versions have to be the same.
		// So we don't have to call DetectBGV twice.
		manifest, err := bpmReader(vdata.BGbpm)
		if err == nil {
			b.Version, _ = cbnt.DetectBGV(manifest)
		}

		_, err = kmReader(vdata.BGkm)
		if err != nil {
			return nil, fmt.Errorf("NewVData: %v", err)
		}
	}

	if vdata.CBNTbpm != nil && vdata.CBNTkm != nil {
		// for CBnT 2.0 KM and BPM will be the same, and for 2.1
		// we only care about version as reported by BPM.
		manifest, err := bpmReader(vdata.CBNTbpm)
		if err == nil {
			b.Version, _ = cbnt.DetectBGV(manifest)
		}

		_, err = kmReader(vdata.CBNTkm)
		if err != nil {
			return nil, fmt.Errorf("NewVData: %v", err)
		}
	}
	if b.Version == 0 {
		return nil, fmt.Errorf("NewVData: can't identify bootguard header")
	}
	b.VData = vdata
	return &b, nil
}

func NewBPM(bpm io.ReadSeeker) (*BootGuard, error) {
	var b BootGuard
	if bpm == nil {
		return nil, fmt.Errorf("manifest is nil")
	}
	var err error
	b.Version, err = cbnt.DetectBGV(bpm)
	if err != nil {
		return nil, err
	}
	switch b.Version {
	case cbnt.Version10:
		bgbpm, err := bootpolicy.NewManifest(cbnt.Version10)
		if err != nil {
			return nil, err
		}
		ast, ok := bgbpm.(*bootpolicy.ManifestBG)
		if !ok {
			return nil, fmt.Errorf("could not assert BPM type")
		}
		b.VData.BGbpm = ast

		_, err = b.VData.BGbpm.ReadFrom(bpm)
		if err != nil && !errors.Is(err, io.EOF) {
			return nil, err
		}
	case cbnt.Version20, cbnt.Version21:
		cbntbpm, err := bootpolicy.NewManifest(cbnt.Version20)
		if err != nil {
			return nil, err
		}
		ast, ok := cbntbpm.(*bootpolicy.ManifestCBnT)
		if !ok {
			return nil, fmt.Errorf("could not assert BPM type")
		}
		b.VData.CBNTbpm = ast

		_, err = b.VData.CBNTbpm.ReadFrom(bpm)
		if err != nil && !errors.Is(err, io.EOF) {
			return nil, err
		}
	default:
		return nil, fmt.Errorf("NewBPM: can't identify bootguard header")
	}
	return &b, nil
}

func NewKM(km io.ReadSeeker) (*BootGuard, error) {
	var b BootGuard
	if km == nil {
		return nil, fmt.Errorf("manifest is nil")
	}
	var err error
	b.Version, err = cbnt.DetectBGV(km)
	if err != nil {
		return nil, err
	}
	switch b.Version {
	case cbnt.Version10:
		bgkm, err := keymanifest.NewManifest(cbnt.Version10)
		if err != nil {
			return nil, err
		}
		ast, ok := bgkm.(*keymanifest.BGManifest)
		if !ok {
			return nil, fmt.Errorf("could not assert KM type")
		}
		b.VData.BGkm = ast

		_, err = b.VData.BGkm.ReadFrom(km)
		if err != nil && !errors.Is(err, io.EOF) {
			return nil, err
		}
	case cbnt.Version20, cbnt.Version21:
		cbntkm, err := keymanifest.NewManifest(b.Version)
		if err != nil {
			return nil, err
		}
		ast, ok := cbntkm.(*keymanifest.CBnTManifest)
		if !ok {
			return nil, fmt.Errorf("could not assert KM type")
		}
		b.VData.CBNTkm = ast

		_, err = b.VData.CBNTkm.ReadFrom(km)
		if err != nil && !errors.Is(err, io.EOF) {
			return nil, err
		}
	default:
		return nil, fmt.Errorf("NewKM: can't identify bootguard header")
	}
	return &b, nil
}

func NewBPMAndKM(bpm io.ReadSeeker, km io.ReadSeeker) (*BootGuard, error) {
	var b BootGuard
	if bpm == nil || km == nil {
		return nil, fmt.Errorf("either both or one manifest is nil")
	}
	bpmV, err := cbnt.DetectBGV(bpm)
	if err != nil {
		return nil, err
	}
	kmV, err := cbnt.DetectBGV(km)
	if err != nil {
		return nil, err
	}
	// This check is not valid for CBnT 2.1 since KM headers were
	// not bumped at all. So the case where km header is 0x21 and
	// bpm is 0x25 is fine.
	if bpmV != kmV && bpmV <= cbnt.Version20 {
		return nil, fmt.Errorf("km and bpm version number differ")
	}
	b.Version = bpmV
	switch b.Version {
	case cbnt.Version10:
		bgbpm, err := bootpolicy.NewManifest(cbnt.Version10)
		if err != nil {
			return nil, err
		}
		astbpm, ok := bgbpm.(*bootpolicy.ManifestBG)
		if !ok {
			return nil, fmt.Errorf("could not assert BPM type")
		}
		b.VData.BGbpm = astbpm

		bgkm, err := keymanifest.NewManifest(cbnt.Version10)
		if err != nil {
			return nil, err
		}
		astkm, ok := bgkm.(*keymanifest.BGManifest)
		if !ok {
			return nil, fmt.Errorf("could not assert KM type")
		}
		b.VData.BGkm = astkm

		_, err = b.VData.BGbpm.ReadFrom(bpm)
		if err != nil && !errors.Is(err, io.EOF) {
			return nil, err
		}
		_, err = b.VData.BGkm.ReadFrom(km)
		if err != nil && !errors.Is(err, io.EOF) {
			return nil, err
		}
	case cbnt.Version20, cbnt.Version21:
		cbntbpm, err := bootpolicy.NewManifest(b.Version)
		if err != nil {
			return nil, err
		}
		astbpm, ok := cbntbpm.(*bootpolicy.ManifestCBnT)
		if !ok {
			return nil, fmt.Errorf("could not assert BPM type")
		}
		b.VData.CBNTbpm = astbpm

		cbntkm, err := keymanifest.NewManifest(cbnt.Version20)
		if err != nil {
			return nil, err
		}
		astkm, ok := cbntkm.(*keymanifest.CBnTManifest)
		if !ok {
			return nil, fmt.Errorf("could not assert KM type")
		}
		b.VData.CBNTkm = astkm

		_, err = b.VData.CBNTbpm.ReadFrom(bpm)
		if err != nil && !errors.Is(err, io.EOF) {
			return nil, err
		}
		_, err = b.VData.CBNTkm.ReadFrom(km)
		if err != nil && !errors.Is(err, io.EOF) {
			return nil, err
		}
	default:
		return nil, fmt.Errorf("NewBPMAndKM: can't identify bootguard header")
	}
	return &b, nil
}

func NewBPMAndKMFromBIOS(biosFilepath string, jsonFilepath *os.File) (*BootGuard, error) {
	bios, err := os.ReadFile(biosFilepath)
	if err != nil {
		return nil, err
	}
	bpmEntry, kmEntry, _, err := ParseFITEntries(bios)
	if err != nil {
		return nil, err
	}
	var b BootGuard
	b.Version, err = cbnt.DetectBGV(bpmEntry.Reader())
	if err != nil {
		return nil, err
	}
	switch b.Version {
	case cbnt.Version10:
		bgbpm, err := bootpolicy.NewManifest(cbnt.Version10)
		if err != nil {
			return nil, err
		}
		bpm, ok := bgbpm.(*bootpolicy.ManifestBG)
		if !ok {
			return nil, fmt.Errorf("could not assert BPM type")
		}
		b.VData.BGbpm = bpm

		bgkm, err := keymanifest.NewManifest(cbnt.Version10)
		if err != nil {
			return nil, err
		}
		km, ok := bgkm.(*keymanifest.BGManifest)
		if !ok {
			return nil, fmt.Errorf("could not assert KM type")
		}
		b.VData.BGkm = km

		_, err = b.VData.BGbpm.ReadFrom(bpmEntry.Reader())
		if err != nil && !errors.Is(err, io.EOF) {
			return nil, err
		}
		_, err = b.VData.BGkm.ReadFrom(kmEntry.Reader())
		if err != nil && !errors.Is(err, io.EOF) {
			return nil, err
		}
	case cbnt.Version20, cbnt.Version21:
		cbntbpm, err := bootpolicy.NewManifest(b.Version)
		if err != nil {
			return nil, err
		}
		bpm, ok := cbntbpm.(*bootpolicy.ManifestCBnT)
		if !ok {
			return nil, fmt.Errorf("could not assert BPM type")
		}
		b.VData.CBNTbpm = bpm

		cbntkm, err := keymanifest.NewManifest(b.Version)
		if err != nil {
			return nil, err
		}
		km, ok := cbntkm.(*keymanifest.CBnTManifest)
		if !ok {
			return nil, fmt.Errorf("could not assert KM type")
		}
		b.VData.CBNTkm = km

		_, err = b.VData.CBNTbpm.ReadFrom(bpmEntry.Reader())
		if err != nil && !errors.Is(err, io.EOF) {
			return nil, err
		}
		_, err = b.VData.CBNTkm.ReadFrom(kmEntry.Reader())
		if err != nil && !errors.Is(err, io.EOF) {
			return nil, err
		}
	default:
		return nil, fmt.Errorf("NewBPMAndKMFromBIOS: can't identify bootguard header")
	}
	data, err := json.Marshal(b.VData)
	if err != nil {
		return nil, err
	}
	json := pretty.Pretty(data)
	if _, err = jsonFilepath.Write(json); err != nil {
		return nil, err
	}
	return &b, nil
}

// ValidateBPM reads from a binary, parses into the boot policy manifest structure
// and validates the structure
func (b *BootGuard) ValidateBPM() error {
	switch b.Version {
	case cbnt.Version10:
		return b.VData.BGbpm.Validate()
	case cbnt.Version20, cbnt.Version21:
		return b.VData.CBNTbpm.Validate()
	default:
		return fmt.Errorf("ValidateBPM: can't identify bootguard header")
	}
}

// ValidateKM reads from a binary source, parses into the key manifest structure
// and validates the structure
func (b *BootGuard) ValidateKM() error {
	switch b.Version {
	case cbnt.Version10:
		return b.VData.BGkm.Validate()
	case cbnt.Version20, cbnt.Version21:
		return b.VData.CBNTkm.Validate()
	default:
		return fmt.Errorf("ValidateKM: can't identify bootguard header")
	}
}

// PrintBPM prints the boot policy manifest in human readable
func (b *BootGuard) PrintBPM() {
	switch b.Version {
	case cbnt.Version10:
		b.VData.BGbpm.Print()
	case cbnt.Version20, cbnt.Version21:
		b.VData.CBNTbpm.Print()
	default:
		log.Error("PrintBPM: can't identify bootguard header")
	}
}

// PrintKM prints the key manifest in human readable
func (b *BootGuard) PrintKM() {
	switch b.Version {
	case cbnt.Version10:
		b.VData.BGkm.Print()
	case cbnt.Version20, cbnt.Version21:
		b.VData.CBNTkm.Print()
	default:
		log.Error("PrintKM: can't identify bootguard header")
	}
}

// WriteKM returns a key manifest as bytes in format defined in #575623.
func (b *BootGuard) WriteKM() ([]byte, error) {
	var err error
	buf := new(bytes.Buffer)
	switch b.Version {
	case cbnt.Version10:
		_, err = b.VData.BGkm.WriteTo(buf)
	case cbnt.Version20, cbnt.Version21:
		_, err = b.VData.CBNTkm.WriteTo(buf)
	default:
		log.Error("WriteKM: can't identify bootguard header")
	}
	return buf.Bytes(), err
}

// WriteBPM returns a boot policy manifest as byte slice
func (b *BootGuard) WriteBPM() ([]byte, error) {
	var err error
	buf := new(bytes.Buffer)
	switch b.Version {
	case cbnt.Version10:
		_, err = b.VData.BGbpm.WriteTo(buf)
	case cbnt.Version20, cbnt.Version21:
		_, err = b.VData.CBNTbpm.WriteTo(buf)
	default:
		log.Error("WriteBPM: can't identify bootguard header")
	}
	return buf.Bytes(), err
}

// WriteJSON returns the entire VData structure in JSON format
func (b *BootGuard) WriteJSON(f *os.File) error {
	cfg, err := json.Marshal(b.VData)
	if err != nil {
		return err
	}
	json := pretty.Pretty(cfg)
	if _, err := f.Write(json); err != nil {
		return err
	}
	return nil
}

// ReadJSON returns the entire VData structure in JSON format
func (b *BootGuard) ReadJSON(filepath string) error {
	data, err := os.ReadFile(filepath)
	if err != nil {
		return err
	}
	if err = json.Unmarshal(data, &b.VData); err != nil {
		return err
	}
	return nil
}

// StitchKM returns a key manifest manifest as byte slice
func (b *BootGuard) StitchKM(pubKey crypto.PublicKey, signature []byte) ([]byte, error) {
	switch b.Version {
	case cbnt.Version10:
		if err := b.VData.BGkm.KeyAndSignature.FillSignature(0, pubKey, signature, b.VData.BGkm.BPKey.HashAlg); err != nil {
			return nil, err
		}
		if err := b.VData.BGkm.Validate(); err != nil {
			return nil, err
		}
	case cbnt.Version20, cbnt.Version21:
		if err := b.VData.CBNTkm.KeyAndSignature.FillSignature(0, pubKey, signature, b.VData.CBNTkm.PubKeyHashAlg); err != nil {
			return nil, err
		}
		b.VData.CBNTkm.RehashRecursive()
		if err := b.VData.CBNTkm.Validate(); err != nil {
			return nil, err
		}
	default:
		log.Error("StitchKM: can't identify bootguard header")
	}
	return b.WriteKM()
}

// StitchBPM returns a boot policy manifest as byte slice
func (b *BootGuard) StitchBPM(pubKey crypto.PublicKey, signature []byte) ([]byte, error) {
	switch b.Version {
	case cbnt.Version10:
		sig, err := bootpolicy.NewSignature(cbnt.Version10)
		if err != nil {
			return nil, err
		}
		b.VData.BGbpm.PMSE = *sig

		if err := b.VData.BGbpm.PMSE.FillSignature(0, pubKey, signature, cbnt.AlgNull); err != nil {
			return nil, err
		}

		b.VData.BGbpm.RehashRecursive()
		if err := b.VData.BGbpm.Validate(); err != nil {
			return nil, err
		}
	case cbnt.Version20, cbnt.Version21:
		sig, err := bootpolicy.NewSignature(cbnt.Version20)
		if err != nil {
			return nil, err
		}
		b.VData.CBNTbpm.PMSE = *sig
		if err := b.VData.CBNTbpm.PMSE.FillSignature(0, pubKey, signature, cbnt.AlgNull); err != nil {
			return nil, err
		}

		b.VData.CBNTbpm.RehashRecursive()
		if err := b.VData.CBNTbpm.Validate(); err != nil {
			return nil, err
		}
	default:
		log.Error("StitchBPM: can't identify bootguard header")
	}
	return b.WriteBPM()
}

// SignKM signs an unsigned KM with signAlgo and private key as input
func (b *BootGuard) SignKM(signAlgo string, signer crypto.Signer) ([]byte, error) {
	buf := new(bytes.Buffer)
	switch b.Version {
	case cbnt.Version10:
		signAlgo, err := cbnt.GetAlgFromString(signAlgo)
		if err != nil {
			return nil, err
		}
		_, err = b.VData.BGkm.WriteTo(buf)
		if err != nil {
			return nil, err
		}
		off, err := b.VData.BGkm.OffsetOf(5)
		if err != nil {
			return nil, err
		}
		unsignedKM := buf.Bytes()[:off]
		// FIXME: second algo here is not needed in BG
		if err := b.VData.BGkm.SetSignature(signAlgo, signAlgo, signer, unsignedKM); err != nil {
			return nil, err
		}
	case cbnt.Version20, cbnt.Version21:
		signAlgo, err := cbnt.GetAlgFromString(signAlgo)
		if err != nil {
			return nil, err
		}
		b.VData.CBNTkm.RehashRecursive()
		_, err = b.VData.CBNTkm.WriteTo(buf)
		if err != nil {
			return nil, err
		}
		v, err := b.VData.CBNTkm.OffsetOf(8)
		if err != nil {
			return nil, err
		}
		unsignedKM := buf.Bytes()[:v]
		if err = b.VData.CBNTkm.SetSignature(signAlgo, b.VData.CBNTkm.PubKeyHashAlg, signer, unsignedKM); err != nil {
			return nil, err
		}
	default:
		log.Error("SignKM: can't identify bootguard header")
	}
	return b.WriteKM()
}

// SignBPM signs an unsigned KM with signAlgo and private key as input
func (b *BootGuard) SignBPM(signAlgo, hashAlgo string, privkey crypto.PrivateKey) ([]byte, error) {
	buf := new(bytes.Buffer)
	switch b.Version {
	case cbnt.Version10:
		signAlgo, err := cbnt.GetAlgFromString(signAlgo)
		if err != nil {
			return nil, err
		}
		sig, err := bootpolicy.NewSignature(cbnt.Version10)
		if err != nil {
			return nil, err
		}
		b.VData.BGbpm.PMSE = *sig
		b.VData.BGbpm.RehashRecursive()
		_, err = b.VData.BGbpm.WriteTo(buf)
		if err != nil {
			return nil, err
		}
		off, err := b.VData.BGbpm.PMSE.OffsetOf(1)
		if err != nil {
			return nil, err
		}
		unsignedBPM := buf.Bytes()[:off]
		if err := b.VData.BGbpm.PMSE.SetSignature(signAlgo, signAlgo, privkey.(crypto.Signer), unsignedBPM); err != nil {
			return nil, err
		}
	case cbnt.Version20, cbnt.Version21:
		signAlgo, err := cbnt.GetAlgFromString(signAlgo)
		if err != nil {
			return nil, err
		}
		hashAlgo, err := cbnt.GetAlgFromString(hashAlgo)
		if err != nil {
			return nil, err
		}
		sig, err := bootpolicy.NewSignature(cbnt.Version20)
		if err != nil {
			return nil, err
		}
		b.VData.CBNTbpm.PMSE = *sig
		b.VData.CBNTbpm.RehashRecursive()
		_, err = b.VData.CBNTbpm.WriteTo(buf)
		if err != nil {
			return nil, err
		}
		unsignedBPM := buf.Bytes()[:b.VData.CBNTbpm.KeySignatureOffset]
		if err = b.VData.CBNTbpm.PMSE.SetSignature(signAlgo, hashAlgo, privkey.(crypto.Signer), unsignedBPM); err != nil {
			return nil, err
		}
	default:
		log.Error("SignBPM: can't identify bootguard header")
	}
	return b.WriteBPM()
}

// VerifyKM verifies a signed KM
func (b *BootGuard) VerifyKM() error {
	buf := new(bytes.Buffer)
	switch b.Version {
	case cbnt.Version10:
		_, err := b.VData.BGkm.WriteTo(buf)
		if err != nil {
			return err
		}
		km := b.VData.BGkm
		off, err := km.OffsetOf(5)
		if err != nil {
			return err
		}
		if err := km.KeyAndSignature.Verify(buf.Bytes()[:off]); err != nil {
			return err
		}
	case cbnt.Version20, cbnt.Version21:
		_, err := b.VData.CBNTkm.WriteTo(buf)
		if err != nil {
			return err
		}

		v, _ := b.VData.CBNTkm.OffsetOf(8)
		if err := b.VData.CBNTkm.KeyAndSignature.Verify(buf.Bytes()[:v]); err != nil {
			return err
		}
	default:
		log.Error("VerifyKM: can't identify bootguard header")
	}
	return nil
}

// VerifyBPM verifies a signed BPM
func (b *BootGuard) VerifyBPM() error {
	buf := new(bytes.Buffer)
	switch b.Version {
	case cbnt.Version10:
		_, err := b.VData.BGbpm.WriteTo(buf)
		if err != nil {
			return err
		}
		off, err := b.VData.BGbpm.OffsetOf(3)
		if err != nil {
			return err
		}
		if err := b.VData.BGbpm.PMSE.Verify(buf.Bytes()[:off]); err != nil {
			return err
		}
	case cbnt.Version20, cbnt.Version21:
		_, err := b.VData.CBNTbpm.WriteTo(buf)
		if err != nil {
			return err
		}
		off := uint64(b.VData.CBNTbpm.BPMHCBnT.KeySignatureOffset)
		if err := b.VData.CBNTbpm.PMSE.Verify(buf.Bytes()[:off]); err != nil {
			return err
		}
	default:
		log.Error("VerifyBPM: can't identify bootguard header")
	}
	return nil
}

// CalculateNEMSize calculates No Eviction Memory and returns it as count of 4K pages.
func (b *BootGuard) CalculateNEMSize(image []byte, acm *tools.ACM) (uint16, error) {
	var totalSize uint32
	if acm == nil {
		return 0, fmt.Errorf("ACM is nil")
	}
	fitTable, err := fit.GetTable(image)
	if err != nil {
		return 0, fmt.Errorf("unable to get FIT: %w", err)
	}
	fitEntries := fitTable.GetEntries(image)
	if len(fitEntries) == 0 || fitEntries[0].GetEntryBase().Headers.Type() != fit.EntryTypeFITHeaderEntry {
		return 0, fmt.Errorf("unable to get FIT headers")
	}
	hdr := fitEntries[0]
	if err != nil {
		return 0, err
	}
	totalSize += keySignatureElementMaxSize
	totalSize += uint32(hdr.GetEntryBase().Headers.Size.Uint32() << 4)
	totalSize += uint32(2048)
	totalSize += keySignatureElementMaxSize
	totalSize += uint32(acm.Header.GetSize().Size())
	totalSize += defaultStackAndDataSize
	switch b.Version {
	case cbnt.Version10:
		totalSize += uint32((&bootpolicy.BPMHBG{}).TotalSize())
		totalSize += uint32(b.VData.BGbpm.SE[0].TotalSize())
		for _, ibb := range b.VData.BGbpm.SE[0].IBBSegments {
			totalSize += ibb.Size
		}
		if b.VData.BGbpm.PME != nil {
			totalSize += uint32(b.VData.BGbpm.PME.DataSize)
		}
		totalSize += uint32(12)
		totalSize += keySignatureElementMaxSize
		if (totalSize + additionalNEMSize) > defaultLLCSize {
			return 0, fmt.Errorf("NEM size is bigger than LLC %d", totalSize+additionalNEMSize)
		}
		if (totalSize % 4096) != 0 {
			totalSize += 4096 - (totalSize % 4096)
		}
		return uint16(bootpolicy.NewSize4K(totalSize)), nil
	case cbnt.Version20, cbnt.Version21:
		totalSize += uint32(b.VData.CBNTkm.KeyManifestSignatureOffset)
		totalSize += uint32((&bootpolicy.BPMHCBnT{}).TotalSize())
		for _, se := range b.VData.CBNTbpm.SE {
			totalSize += uint32(se.ElementSize)
			for _, ibb := range se.IBBSegments {
				totalSize += ibb.Size
			}
		}
		if b.VData.CBNTbpm.PCDE != nil {
			totalSize += uint32(b.VData.CBNTbpm.PCDE.ElementSize)
		}
		if b.VData.CBNTbpm.PME != nil {
			totalSize += uint32(b.VData.CBNTbpm.PME.ElementSize)
		}
		totalSize += uint32(12)
		totalSize += keySignatureElementMaxSize
		if b.VData.CBNTbpm.TXTE != nil {
			totalSize += uint32(b.VData.CBNTbpm.TXTE.ElementSize)
		}
		if (totalSize + additionalNEMSize) > defaultLLCSize {
			return 0, fmt.Errorf("NEM size is bigger than LLC %d", totalSize+additionalNEMSize)
		}
		if (totalSize % 4096) != 0 {
			totalSize += 4096 - (totalSize % 4096)
		}
		return uint16(bootpolicy.NewSize4K(totalSize)), nil
	default:
		return 0, fmt.Errorf("CalculateNEMSize: can't identify bootguard header")
	}
}

// GetBPMPubHash takes the path to public BPM signing key and hash algorithm
// and returns a hash with hashAlg of pub BPM singing key
func (b *BootGuard) GetBPMPubHash(pubkey crypto.PublicKey, hashAlgo string) error {
	var data []byte
	var kAs cbnt.Key
	if err := kAs.SetPubKey(pubkey); err != nil {
		return err
	}
	switch b.Version {
	case cbnt.Version10:
		hashAlg, err := cbnt.GetAlgFromString(hashAlgo)
		if err != nil {
			return err
		}
		hash, err := hashAlg.Hash()
		if err != nil {
			return err
		}
		k := kAs.Data[4:]
		if _, err := hash.Write(k); err != nil {
			return err
		}
		data = hash.Sum(nil)
		hStruc := cbnt.HashStructure{
			HashAlg: cbnt.Algorithm(hashAlg),
		}
		hStruc.HashBuffer = data
		b.VData.BGkm.BPKey = hStruc
	case cbnt.Version20, cbnt.Version21:
		hashAlg, err := cbnt.GetAlgFromString(hashAlgo)
		if err != nil {
			return err
		}
		hash, err := hashAlg.Hash()
		if err != nil {
			return err
		}
		k := kAs.Data[4:]
		if _, err := hash.Write(k); err != nil {
			return err
		}
		data = hash.Sum(nil)
		var keyHashes []keymanifest.Hash
		hStruc := &cbnt.HashStructure{
			HashAlg: cbnt.Algorithm(hashAlg),
		}
		hStruc.HashBuffer = data

		kH := keymanifest.Hash{
			Usage:  keymanifest.UsageBPMSigningPKD,
			Digest: *hStruc,
		}
		b.VData.CBNTkm.Hash = append(keyHashes, kH)
	default:
		log.Error("can't identify bootguard header")
	}
	return nil
}

func (b *BootGuard) GetIBBsDigest(image []byte, hashAlgo string) (digest []byte, err error) {
	switch b.Version {
	case cbnt.Version10:
		hashAlg, err := cbnt.GetAlgFromString(hashAlgo)
		if err != nil {
			return nil, err
		}
		hash, err := hashAlg.Hash()
		if err != nil {
			return nil, err
		}
		ibbs := b.VData.BGbpm.SE[0].IBBSegments
		reader := bytes.NewReader(image)
		ibbSegments := make([][]byte, len(ibbs))
		for idx, ibb := range ibbs {
			if ibb.Flags&(1<<0) != 0 {
				continue
			}
			addr, err := tools.CalcImageOffset(image, uint64(ibb.Base))
			if err != nil {
				return nil, fmt.Errorf("unable to calculate the offset: %w", err)
			}
			_, err = reader.Seek(int64(addr), io.SeekStart)
			if err != nil {
				return nil, fmt.Errorf("got error from Seek: %w", err)
			}
			size := uint64(ibb.Size)
			ibbSegments[idx] = make([]byte, size)
			_, err = reader.Read(ibbSegments[idx])
			if err != nil {
				return nil, fmt.Errorf("unable to read the segment: %w", err)
			}
		}
		for _, segment := range ibbSegments {
			_, err = hash.Write(segment)
			if err != nil {
				return nil, err
			}
		}
		digest = hash.Sum(nil)
	case cbnt.Version20, cbnt.Version21:
		hashAlg, err := cbnt.GetAlgFromString(hashAlgo)
		if err != nil {
			return nil, err
		}
		hash, err := hashAlg.Hash()
		if err != nil {
			return nil, err
		}
		ibbs := b.VData.CBNTbpm.SE[0].IBBSegments
		reader := bytes.NewReader(image)
		ibbSegments := make([][]byte, len(ibbs))
		for idx, ibb := range ibbs {
			if ibb.Flags&(1<<0) != 0 {
				continue
			}
			addr, err := tools.CalcImageOffset(image, uint64(ibb.Base))
			if err != nil {
				return nil, fmt.Errorf("unable to calculate the offset: %w", err)
			}
			_, err = reader.Seek(int64(addr), io.SeekStart)
			if err != nil {
				return nil, fmt.Errorf("got error from Seek: %w", err)
			}
			size := uint64(ibb.Size)
			ibbSegments[idx] = make([]byte, size)
			_, err = reader.Read(ibbSegments[idx])
			if err != nil {
				return nil, fmt.Errorf("unable to read the segment: %w", err)
			}
		}
		for _, segment := range ibbSegments {
			_, err = hash.Write(segment)
			if err != nil {
				return nil, err
			}
		}
		digest = hash.Sum(nil)
	default:
		log.Error("can't identify bootguard header")
	}
	return digest, nil
}

// CreateIBBDigest generates a Boot Policy Manifest with the given config and firmware image
func (b *BootGuard) CreateIBBDigest(biosFilepath string) error {
	data, err := os.ReadFile(biosFilepath)
	if err != nil {
		return fmt.Errorf("unable to read file '%s': %w", biosFilepath, err)
	}
	switch b.Version {
	case cbnt.Version10:
		hashAlgo := b.VData.BGbpm.SE[0].Digest.HashAlg.String()
		d, err := b.GetIBBsDigest(data, hashAlgo)
		if err != nil {
			return fmt.Errorf("unable to getIBBsDigest for %v: %w", hashAlgo, err)
		}
		b.VData.BGbpm.SE[0].Digest.HashBuffer = make([]byte, len(d))
		copy(b.VData.BGbpm.SE[0].Digest.HashBuffer, d)
	case cbnt.Version20, cbnt.Version21:
		for iterator, item := range b.VData.CBNTbpm.SE[0].DigestList.List {
			d, err := b.GetIBBsDigest(data, item.HashAlg.String())
			if err != nil {
				return fmt.Errorf("unable to getIBBsDigest for %v: %w", item.HashAlg, err)
			}
			b.VData.CBNTbpm.SE[0].DigestList.List[iterator].HashBuffer = make([]byte, len(d))
			copy(b.VData.CBNTbpm.SE[0].DigestList.List[iterator].HashBuffer, d)
		}
	default:
		log.Error("can't identify bootguard header")
	}
	return nil
}

// BPMCryptoSecure verifies that BPM uses sane crypto algorithms
func (b *BootGuard) BPMCryptoSecure() (bool, error) {
	switch b.Version {
	case cbnt.Version10:
		hash := b.VData.BGbpm.SE[0].Digest.HashAlg
		if hash == cbnt.AlgSHA1 || hash.IsNull() {
			return false, fmt.Errorf("signed IBB hash in BPM uses insecure hash algorithm SHA1/Null")
		}
		hash = b.VData.BGbpm.PMSE.Signature.HashAlg
		if hash == cbnt.AlgSHA1 || hash.IsNull() {
			return false, fmt.Errorf("BPM signature uses insecure hash algorithm SHA1/Null")
		}
	case cbnt.Version20, cbnt.Version21:
		for _, hash := range b.VData.CBNTbpm.SE[0].DigestList.List {
			if hash.HashAlg == cbnt.AlgSHA1 || hash.HashAlg.IsNull() {
				if b.VData.CBNTbpm.SE[0].DigestList.Size < 2 {
					return false, fmt.Errorf("signed IBB hash list in BPM uses insecure hash algorithm SHA1/Null")
				}
			}
		}
		hash := b.VData.CBNTbpm.PMSE.Signature.HashAlg
		if hash == cbnt.AlgSHA1 || hash.IsNull() {
			return false, fmt.Errorf("BPM signature uses insecure hash algorithm SHA1/Null")
		}
	}
	return true, nil
}

// KMCryptoSecure verifies that KM uses sane crypto algorithms
func (b *BootGuard) KMCryptoSecure() (bool, error) {
	switch b.Version {
	case cbnt.Version10:
		hash := b.VData.BGkm.KeyAndSignature.Signature.HashAlg
		if hash == cbnt.AlgSHA1 || hash.IsNull() {
			return false, fmt.Errorf("KM signature uses insecure hash algorithm SHA1/Null")
		}
		hash = b.VData.BGkm.BPKey.HashAlg
		if hash == cbnt.AlgSHA1 || hash.IsNull() {
			return false, fmt.Errorf("signed BPM hash in KM uses insecure hash algorithm SHA1/Null")
		}
	case cbnt.Version20, cbnt.Version21:
		hash := b.VData.CBNTkm.PubKeyHashAlg
		if hash == cbnt.AlgSHA1 || hash.IsNull() {
			return false, fmt.Errorf("KM signature uses insecure hash algorithm SHA1/Null")
		}
		for _, hash := range b.VData.CBNTkm.Hash {
			if hash.Digest.HashAlg == cbnt.AlgSHA1 || hash.Digest.HashAlg.IsNull() {
				return false, fmt.Errorf("the KM hash %s uses insecure hash algorithm SHA1/Null", hash.Usage.String())
			}
		}
	}
	return true, nil
}

// KMHasBPMHash verifies that KM has the correctly signed BPM hash
func (b *BootGuard) KMHasBPMHash() (bool, error) {
	var bpmHashFound bool
	switch b.Version {
	case cbnt.Version10:
		size, err := b.VData.BGkm.BPKey.SizeOf(1)
		if err != nil {
			return false, err
		}
		if size > minHashTypeSize {
			bpmHashFound = true
		}
	case cbnt.Version20, cbnt.Version21:
		for _, hash := range b.VData.CBNTkm.Hash {
			if hash.Usage == keymanifest.UsageBPMSigningPKD {
				bpmHashFound = true
			}
		}
	}
	if !bpmHashFound {
		return false, fmt.Errorf("couldn't find BPM hash in KM")
	}
	return true, nil
}

// BPMKeyMatchKMHash verifies that BPM pubkey hash matches KM hash of Boot Policy
func (b *BootGuard) BPMKeyMatchKMHash() (bool, error) {
	switch b.Version {
	case cbnt.Version10:
		size, err := b.VData.BGkm.BPKey.SizeOf(1)
		if err != nil {
			return false, err
		}
		if size > minHashTypeSize {
			if err := b.VData.BGkm.ValidateBPMKey(b.VData.BGbpm.PMSE.KeySignature); err != nil {
				return false, fmt.Errorf("couldn't verify bpm hash in km")
			}
		}
	case cbnt.Version20, cbnt.Version21:
		for _, hash := range b.VData.CBNTkm.Hash {
			if hash.Usage == keymanifest.UsageBPMSigningPKD {
				if err := b.VData.CBNTkm.ValidateBPMKey(b.VData.CBNTbpm.PMSE.KeySignature); err != nil {
					return false, fmt.Errorf("couldn't verify bpm hash in km")
				}
			}
		}
	}
	return true, nil
}

// StrictSaneBPMSecurityProps verifies that BPM contains security properties more strictly
func (b *BootGuard) StrictSaneBPMSecurityProps() (bool, []string, error) {
	var warn []string
	switch b.Version {
	case cbnt.Version10:
		flags := b.VData.BGbpm.SE[0].Flags
		if !flags.AuthorityMeasure() {
			return false, nil, fmt.Errorf("pcr-7 data should extended for OS security")
		}
		if !flags.TPMFailureLeavesHierarchiesEnabled() {
			warn = append(warn, "tpm failure should lead to default measurements from PCR0 to PCR7")
		}
	case cbnt.Version20, cbnt.Version21:
		bgFlags := b.VData.CBNTbpm.SE[0].Flags
		if !bgFlags.AuthorityMeasure() && b.Version != cbnt.Version21 {
			return false, nil, fmt.Errorf("pcr-7 data should extended for OS security")
		}
		if !bgFlags.TPMFailureLeavesHierarchiesEnabled() {
			warn = append(warn, "tpm failure should lead to default measurements from PCR0 to PCR7")
		}
		txtFlags := b.VData.CBNTbpm.TXTE.ControlFlags
		if txtFlags.MemoryScrubbingPolicy() != bootpolicy.MemoryScrubbingPolicySACM {
			warn = append(warn, "S-ACM memory scrubbing should be used over the BIOS")
		}
	}
	ret, err := b.SaneBPMSecurityProps()
	return ret, warn, err
}

// SaneBPMSecurityProps verifies that BPM contains security properties set accordingly to spec
func (b *BootGuard) SaneBPMSecurityProps() (bool, error) {
	switch b.Version {
	case cbnt.Version10:
		flags := b.VData.BGbpm.SE[0].Flags
		if !flags.DMAProtection() {
			return false, fmt.Errorf("dma protection should be enabled for bootguard")
		}
		if !flags.AuthorityMeasure() {
			return false, fmt.Errorf("pcr-7 data should extended for OS security")
		}
		if b.VData.BGbpm.SE[0].PBETValue.PBETValue() == 0 {
			return false, fmt.Errorf("firmware shall not allowed to run infinitely after incident happened")
		}
		if len(b.VData.BGbpm.SE[0].IBBSegments) < 1 {
			return false, fmt.Errorf("no ibb segments measured")
		}
	case cbnt.Version20, cbnt.Version21:
		bgFlags := b.VData.CBNTbpm.SE[0].Flags
		if !bgFlags.DMAProtection() {
			if b.VData.CBNTbpm.SE[0].DMAProtBase0 == 0 && b.VData.CBNTbpm.SE[0].VTdBAR == 0 {
				return false, fmt.Errorf("dma protection should be enabled for bootguard")
			}
		}
		// PCR7 is not available since MTL
		if b.VData.CBNTbpm.BPMHCBnT.StructInfoCBNT.Version < 0x25 && !bgFlags.AuthorityMeasure() {
			return false, fmt.Errorf("pcr-7 data should extended for OS security")
		}
		if b.VData.CBNTbpm.SE[0].PBETValue.PBETValue() == 0 {
			return false, fmt.Errorf("firmware shall not allowed to run infinitely after incident happened")
		}
		txtFlags := b.VData.CBNTbpm.TXTE.ControlFlags
		if !txtFlags.IsSACMRequestedToExtendStaticPCRs() {
			return false, fmt.Errorf("S-ACM shall always extend static PCRs")
		}
		if len(b.VData.CBNTbpm.SE[0].IBBSegments) < 1 {
			return false, fmt.Errorf("no ibb segments measured")
		}
	}
	return true, nil
}

// IBBsMatchBPMDigest verifies that FIT measurements match final digest in BPM
func (b *BootGuard) IBBsMatchBPMDigest(image []byte) (bool, error) {
	firmware, err := uefi.Parse(image)
	if err != nil {
		return false, fmt.Errorf("can't parse firmware image")
	}
	switch b.Version {
	case cbnt.Version10:
		if err := b.VData.BGbpm.ValidateIBB(firmware); err != nil {
			return false, fmt.Errorf("bpm final ibb hash doesn't match selected measurements in image: %w", err)
		}
	case cbnt.Version20, cbnt.Version21:
		if err := b.VData.CBNTbpm.ValidateIBB(firmware); err != nil {
			return false, fmt.Errorf("bpm final ibb hash doesn't match selected measurements in image: %w", err)
		}
	}
	return true, nil
}

// ValidateMEAgainstManifests validates during runtime ME configuation with BootGuard KM & BPM manifests
func (b *BootGuard) ValidateMEAgainstManifests(fws *FirmwareStatus) (bool, error) {
	switch b.Version {
	case cbnt.Version10:
		if fws.Status6.BPMSVN != uint32(b.VData.BGbpm.BPMSVN) {
			return false, fmt.Errorf("bpm svn doesn't match me configuration")
		}
		if fws.Status6.KMSVN != uint32(b.VData.BGkm.KMSVN) {
			return false, fmt.Errorf("km svn doesn't match me configuration")
		}
		if fws.Status6.KMID != uint32(b.VData.BGkm.KMID) {
			return false, fmt.Errorf("km KMID doesn't match me configuration")
		}
	case cbnt.Version20:
		if fws.Status6.BPMSVN > uint32(b.VData.CBNTbpm.BPMSVN) {
			return false, fmt.Errorf("bpm svn doesn't match me configuration")
		}
		if fws.Status6.KMSVN != uint32(b.VData.CBNTkm.KMSVN) {
			return false, fmt.Errorf("km svn doesn't match me configuration")
		}
		if fws.Status6.KMID != uint32(b.VData.CBNTkm.KMID) {
			return false, fmt.Errorf("km KMID doesn't match me configuration")
		}
	}
	return true, nil
}

// CreateIBBSegments takes a firmware image, searches files for
// additional IBBSegment, supports coreboot and UEFI EDK2
func (b *BootGuard) CreateIBBSegments(seElement uint8, flags uint16, imagepath string) error {
	image, err := os.Open(imagepath)
	if err != nil {
		return err
	}
	defer func() {
		if err := image.Close(); err != nil {
			log.Warnf("failed to close the file: %v\n", err)
		}
	}()
	stat, err := image.Stat()
	if err != nil {
		return err
	}
	type ibbElement struct {
		Reserved [2]byte
		Flags    uint16
		Base     uint32
		Size     uint32
	}
	var ibbElements []ibbElement
	img, err := cbfs.NewImage(image)
	if err != nil {
		// To be sure the image file is closed before reading from it again
		err := image.Close()
		if err != nil {
			return err
		}
		img, err := os.ReadFile(imagepath)
		if err != nil {
			return err
		}
		fitentries, err := fit.GetEntries(img)
		if err != nil {
			return err
		}
		var ibbCount uint8
		for _, entry := range fitentries {
			if entry.GetEntryBase().Headers.Type() == fit.EntryTypeBIOSStartupModuleEntry {
				ibbCount++
			}
		}
		ibbElements = make([]ibbElement, ibbCount)
		for idx, entry := range fitentries {
			if entry.GetEntryBase().Headers.Type() == fit.EntryTypeBIOSStartupModuleEntry {
				ibbElements[idx].Base = uint32(entry.GetEntryBase().Headers.Address.Pointer())
				ibbElements[idx].Size = entry.GetEntryBase().Headers.Size.Uint32() << 4
				ibbElements[idx].Flags = flags
			}
		}
	} else {
		// From here we consider it is a coreboot image
		flashBase := consts.BasePhysAddr - stat.Size()
		cbfsbaseaddr := img.Area.Offset
		var ibbCount uint8
		for _, seg := range img.Segs {
			switch seg.GetFile().Name {
			case
				"fspt.bin",
				"fallback/verstage",
				"bootblock":
				ibbCount++
			}
		}
		ibbElements = make([]ibbElement, ibbCount)
		for idx, seg := range img.Segs {
			switch seg.GetFile().Name {
			case
				"fspt.bin",
				"fallback/verstage",
				"bootblock":

				ibbElements[idx].Base = uint32(flashBase) + cbfsbaseaddr + seg.GetFile().RecordStart + seg.GetFile().SubHeaderOffset
				ibbElements[idx].Size = seg.GetFile().Size
				ibbElements[idx].Flags = flags
			}
		}
	}
	switch b.Version {
	case cbnt.Version10:
		b.VData.BGbpm.SE[seElement].IBBSegments = make([]bootpolicy.IBBSegment, len(ibbElements))
		for idx, ibb := range ibbElements {
			b.VData.BGbpm.SE[seElement].IBBSegments[idx].Base = ibb.Base
			b.VData.BGbpm.SE[seElement].IBBSegments[idx].Size = ibb.Size
			b.VData.BGbpm.SE[seElement].IBBSegments[idx].Flags = ibb.Flags
		}
	case cbnt.Version20, cbnt.Version21:
		b.VData.CBNTbpm.SE[seElement].IBBSegments = make([]bootpolicy.IBBSegment, len(ibbElements))
		for idx, ibb := range ibbElements {
			b.VData.CBNTbpm.SE[seElement].IBBSegments[idx].Base = ibb.Base
			b.VData.CBNTbpm.SE[seElement].IBBSegments[idx].Size = ibb.Size
			b.VData.CBNTbpm.SE[seElement].IBBSegments[idx].Flags = ibb.Flags
		}
	}
	return nil
}
