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
	"github.com/linuxboot/fiano/pkg/intel/metadata/bg"
	"github.com/linuxboot/fiano/pkg/intel/metadata/bg/bgbootpolicy"
	"github.com/linuxboot/fiano/pkg/intel/metadata/bg/bgkey"
	"github.com/linuxboot/fiano/pkg/intel/metadata/cbnt"
	"github.com/linuxboot/fiano/pkg/intel/metadata/cbnt/cbntbootpolicy"
	"github.com/linuxboot/fiano/pkg/intel/metadata/cbnt/cbntkey"
	"github.com/linuxboot/fiano/pkg/intel/metadata/common/bgheader"
	"github.com/linuxboot/fiano/pkg/intel/metadata/fit"
	"github.com/linuxboot/fiano/pkg/uefi"
	"github.com/tidwall/pretty"

	log "github.com/sirupsen/logrus"
	"go.uber.org/multierr"
)

// Everything more secure than SHA-1
const minHashTypeSize = 32

func bgBPMReader(bpm *bgbootpolicy.Manifest) (*bytes.Reader, error) {
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

func bgKMReader(km *bgkey.Manifest) (*bytes.Reader, error) {
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

func cbntBPMReader(bpm *cbntbootpolicy.Manifest) (*bytes.Reader, error) {
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

func cbntKMReader(km *cbntkey.Manifest) (*bytes.Reader, error) {
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
	var err error
	manifest, err := bgBPMReader(vdata.BGbpm)
	if err == nil {
		b.Version, _ = bgheader.DetectBGV(manifest)
	}
	manifest, err = bgKMReader(vdata.BGkm)
	if err == nil {
		b.Version, _ = bgheader.DetectBGV(manifest)
	}
	manifest, err = cbntBPMReader(vdata.CBNTbpm)
	if err == nil {
		b.Version, _ = bgheader.DetectBGV(manifest)
	}
	manifest, err = cbntKMReader(vdata.CBNTkm)
	if err == nil {
		b.Version, _ = bgheader.DetectBGV(manifest)
	}
	if b.Version == 0 {
		return nil, fmt.Errorf("NewVData: can't identify BootGuard header")
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
	b.Version, err = bgheader.DetectBGV(bpm)
	if err != nil {
		return nil, err
	}
	switch b.Version {
	case bgheader.Version10:
		b.VData.BGbpm = bgbootpolicy.NewManifest()
		_, err = b.VData.BGbpm.ReadFrom(bpm)
		if err != nil && !errors.Is(err, io.EOF) {
			return nil, err
		}
	case bgheader.Version20:
		b.VData.CBNTbpm = cbntbootpolicy.NewManifest()
		_, err = b.VData.CBNTbpm.ReadFrom(bpm)
		if err != nil && !errors.Is(err, io.EOF) {
			return nil, err
		}
	default:
		return nil, fmt.Errorf("NewBPM: can't identify BootGuard header")
	}
	return &b, nil
}

func NewKM(km io.ReadSeeker) (*BootGuard, error) {
	var b BootGuard
	if km == nil {
		return nil, fmt.Errorf("manifest is nil")
	}
	var err error
	b.Version, err = bgheader.DetectBGV(km)
	if err != nil {
		return nil, err
	}
	switch b.Version {
	case bgheader.Version10:
		b.VData.BGkm = bgkey.NewManifest()
		_, err = b.VData.BGkm.ReadFrom(km)
		if err != nil && !errors.Is(err, io.EOF) {
			return nil, err
		}
	case bgheader.Version20:
		b.VData.CBNTkm = cbntkey.NewManifest()
		_, err = b.VData.CBNTkm.ReadFrom(km)
		if err != nil && !errors.Is(err, io.EOF) {
			return nil, err
		}
	default:
		return nil, fmt.Errorf("NewKM: can't identify BootGuard header")
	}
	return &b, nil
}

func NewBPMAndKM(bpm io.ReadSeeker, km io.ReadSeeker) (*BootGuard, error) {
	var b BootGuard
	if bpm == nil || km == nil {
		return nil, fmt.Errorf("either both or one manifest is nil")
	}
	var err error
	bpmV, err := bgheader.DetectBGV(bpm)
	if err != nil {
		return nil, err
	}
	kmV, err := bgheader.DetectBGV(km)
	if err != nil {
		return nil, err
	}
	if bpmV != kmV {
		return nil, fmt.Errorf("Key Manifest and Boot Policy Manifest version number differ")
	}
	b.Version = bpmV
	switch b.Version {
	case bgheader.Version10:
		b.VData.BGbpm = bgbootpolicy.NewManifest()
		b.VData.BGkm = bgkey.NewManifest()
		_, err := b.VData.BGbpm.ReadFrom(bpm)
		if err != nil && !errors.Is(err, io.EOF) {
			return nil, err
		}
		_, err = b.VData.BGkm.ReadFrom(km)
		if err != nil && !errors.Is(err, io.EOF) {
			return nil, err
		}
	case bgheader.Version20:
		b.VData.CBNTbpm = cbntbootpolicy.NewManifest()
		b.VData.CBNTkm = cbntkey.NewManifest()
		_, err := b.VData.CBNTbpm.ReadFrom(bpm)
		if err != nil && !errors.Is(err, io.EOF) {
			return nil, err
		}
		_, err = b.VData.CBNTkm.ReadFrom(km)
		if err != nil && !errors.Is(err, io.EOF) {
			return nil, err
		}
	default:
		return nil, fmt.Errorf("NewBPMAndKM: can't identify BootGuard header")
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
	b.Version, err = bgheader.DetectBGV(bpmEntry.Reader())
	if err != nil {
		return nil, err
	}
	switch b.Version {
	case bgheader.Version10:
		b.VData.BGbpm = bgbootpolicy.NewManifest()
		b.VData.BGkm = bgkey.NewManifest()
		_, err := b.VData.BGbpm.ReadFrom(bpmEntry.Reader())
		if err != nil && !errors.Is(err, io.EOF) {
			return nil, err
		}
		_, err = b.VData.BGkm.ReadFrom(kmEntry.Reader())
		if err != nil && !errors.Is(err, io.EOF) {
			return nil, err
		}
	case bgheader.Version20:
		b.VData.CBNTbpm = cbntbootpolicy.NewManifest()
		b.VData.CBNTkm = cbntkey.NewManifest()
		_, err := b.VData.CBNTbpm.ReadFrom(bpmEntry.Reader())
		if err != nil && !errors.Is(err, io.EOF) {
			return nil, err
		}
		_, err = b.VData.CBNTkm.ReadFrom(kmEntry.Reader())
		if err != nil && !errors.Is(err, io.EOF) {
			return nil, err
		}
	default:
		return nil, fmt.Errorf("NewBPMAndKMFromBIOS: can't identify BootGuard header")
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
	case bgheader.Version10:
		return b.VData.BGbpm.Validate()
	case bgheader.Version20:
		return b.VData.CBNTbpm.Validate()
	default:
		return fmt.Errorf("ValidateBPM: can't identify BootGuard header")
	}
}

// ValidateKM reads from a binary source, parses into the Key Manifest structure
// and validates the structure
func (b *BootGuard) ValidateKM() error {
	switch b.Version {
	case bgheader.Version10:
		return b.VData.BGkm.Validate()
	case bgheader.Version20:
		return b.VData.CBNTkm.Validate()
	default:
		return fmt.Errorf("ValidateKM: can't identify BootGuard header")
	}
}

// PrintBPM prints the boot policy manifest in human readable
func (b *BootGuard) PrintBPM() {
	switch b.Version {
	case bgheader.Version10:
		b.VData.BGbpm.Print()
	case bgheader.Version20:
		b.VData.CBNTbpm.Print()
	default:
		log.Error("PrintBPM: can't identify BootGuard header")
	}
}

// PrintKM prints the Key Manifest in human readable
func (b *BootGuard) PrintKM() {
	switch b.Version {
	case bgheader.Version10:
		b.VData.BGkm.Print()
	case bgheader.Version20:
		b.VData.CBNTkm.Print()
	default:
		log.Error("PrintKM: can't identify BootGuard header")
	}
}

// WriteKM returns a Key Manifest as bytes in format defined in #575623.
func (b *BootGuard) WriteKM() ([]byte, error) {
	var err error
	buf := new(bytes.Buffer)
	switch b.Version {
	case bgheader.Version10:
		_, err = b.VData.BGkm.WriteTo(buf)
	case bgheader.Version20:
		_, err = b.VData.CBNTkm.WriteTo(buf)
	default:
		log.Error("WriteKM: can't identify BootGuard header")
	}
	return buf.Bytes(), err
}

// WriteBPM returns a boot policy manifest as byte slice
func (b *BootGuard) WriteBPM() ([]byte, error) {
	var err error
	buf := new(bytes.Buffer)
	switch b.Version {
	case bgheader.Version10:
		_, err = b.VData.BGbpm.WriteTo(buf)
	case bgheader.Version20:
		_, err = b.VData.CBNTbpm.WriteTo(buf)
	default:
		log.Error("WriteBPM: can't identify BootGuard header")
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

// StitchKM returns a Key Manifest as byte slice
func (b *BootGuard) StitchKM(pubKey crypto.PublicKey, signature []byte) ([]byte, error) {
	switch b.Version {
	case bgheader.Version10:
		if err := b.VData.BGkm.KeyAndSignature.FillSignature(0, pubKey, signature, b.VData.BGkm.BPKey.HashAlg); err != nil {
			return nil, err
		}
		b.VData.BGkm.RehashRecursive()
		if err := b.VData.BGkm.Validate(); err != nil {
			return nil, err
		}
	case bgheader.Version20:
		if err := b.VData.CBNTkm.KeyAndSignature.FillSignature(0, pubKey, signature, b.VData.CBNTkm.PubKeyHashAlg); err != nil {
			return nil, err
		}
		b.VData.CBNTkm.RehashRecursive()
		if err := b.VData.CBNTkm.Validate(); err != nil {
			return nil, err
		}
	default:
		log.Error("StitchKM: can't identify BootGuard header")
	}
	return b.WriteKM()
}

// StitchBPM returns a boot policy manifest as byte slice
func (b *BootGuard) StitchBPM(pubKey crypto.PublicKey, signature []byte) ([]byte, error) {
	switch b.Version {
	case bgheader.Version10:
		b.VData.BGbpm.PMSE = *bgbootpolicy.NewSignature()
		if err := b.VData.BGbpm.PMSE.KeySignature.FillSignature(0, pubKey, signature, bg.AlgNull); err != nil {
			return nil, err
		}

		b.VData.BGbpm.RehashRecursive()
		if err := b.VData.BGbpm.Validate(); err != nil {
			return nil, err
		}
	case bgheader.Version20:
		b.VData.CBNTbpm.PMSE = *cbntbootpolicy.NewSignature()
		if err := b.VData.CBNTbpm.PMSE.KeySignature.FillSignature(0, pubKey, signature, cbnt.AlgNull); err != nil {
			return nil, err
		}

		b.VData.CBNTbpm.RehashRecursive()
		if err := b.VData.CBNTbpm.Validate(); err != nil {
			return nil, err
		}
	default:
		log.Error("StitchBPM: can't identify BootGuard header")
	}
	return b.WriteBPM()
}

// SignKM signs an unsigned KM with signAlgo and private key as input
func (b *BootGuard) SignKM(signAlgo string, privkey crypto.PrivateKey) ([]byte, error) {
	buf := new(bytes.Buffer)
	switch b.Version {
	case bgheader.Version10:
		signAlgo, err := bg.GetAlgFromString(signAlgo)
		if err != nil {
			return nil, err
		}
		b.VData.BGkm.RehashRecursive()
		_, err = b.VData.BGkm.WriteTo(buf)
		if err != nil {
			return nil, err
		}
		unsignedKM := buf.Bytes()[:b.VData.BGkm.KeyAndSignatureOffset()]
		if err := b.VData.BGkm.SetSignature(signAlgo, privkey.(crypto.Signer), unsignedKM); err != nil {
			return nil, err
		}
	case bgheader.Version20:
		signAlgo, err := cbnt.GetAlgFromString(signAlgo)
		if err != nil {
			return nil, err
		}
		b.VData.CBNTkm.RehashRecursive()
		_, err = b.VData.CBNTkm.WriteTo(buf)
		if err != nil {
			return nil, err
		}
		unsignedKM := buf.Bytes()[:b.VData.CBNTkm.KeyAndSignatureOffset()]
		if err = b.VData.CBNTkm.SetSignature(signAlgo, b.VData.CBNTkm.PubKeyHashAlg, privkey.(crypto.Signer), unsignedKM); err != nil {
			return nil, err
		}
	default:
		log.Error("SignKM: can't identify BootGuard header")
	}
	return b.WriteKM()
}

// SignBPM signs an unsigned KM with signAlgo and private key as input
func (b *BootGuard) SignBPM(signAlgo, hashAlgo string, privkey crypto.PrivateKey) ([]byte, error) {
	buf := new(bytes.Buffer)
	switch b.Version {
	case bgheader.Version10:
		signAlgo, err := bg.GetAlgFromString(signAlgo)
		if err != nil {
			return nil, err
		}
		b.VData.BGbpm.PMSE = *bgbootpolicy.NewSignature()
		b.VData.BGbpm.RehashRecursive()
		_, err = b.VData.BGbpm.WriteTo(buf)
		if err != nil {
			return nil, err
		}
		unsignedBPM := buf.Bytes()[:b.VData.BGbpm.PMSE.KeySignatureOffset()]
		if err := b.VData.BGbpm.PMSE.SetSignature(signAlgo, privkey.(crypto.Signer), unsignedBPM); err != nil {
			return nil, err
		}
	case bgheader.Version20:
		signAlgo, err := cbnt.GetAlgFromString(signAlgo)
		if err != nil {
			return nil, err
		}
		hashAlgo, err := cbnt.GetAlgFromString(hashAlgo)
		if err != nil {
			return nil, err
		}
		b.VData.CBNTbpm.PMSE = *cbntbootpolicy.NewSignature()
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
		log.Error("SignBPM: can't identify BootGuard header")
	}
	return b.WriteBPM()
}

// VerifyKM verifies a signed KM
func (b *BootGuard) VerifyKM() error {
	buf := new(bytes.Buffer)
	switch b.Version {
	case bgheader.Version10:
		_, err := b.VData.BGkm.WriteTo(buf)
		if err != nil {
			return err
		}
		if err := b.VData.BGkm.KeyAndSignature.Verify(buf.Bytes()[:b.VData.BGkm.KeyAndSignatureOffset()]); err != nil {
			return err
		}
	case bgheader.Version20:
		_, err := b.VData.CBNTkm.WriteTo(buf)
		if err != nil {
			return err
		}
		if err := b.VData.CBNTkm.KeyAndSignature.Verify(buf.Bytes()[:b.VData.CBNTkm.KeyAndSignatureOffset()]); err != nil {
			return err
		}
	default:
		log.Error("VerifyKM: can't identify BootGuard header")
	}
	return nil
}

// VerifyBPM verifies a signed BPM
func (b *BootGuard) VerifyBPM() error {
	buf := new(bytes.Buffer)
	switch b.Version {
	case bgheader.Version10:
		_, err := b.VData.BGbpm.WriteTo(buf)
		if err != nil {
			return err
		}
		if err := b.VData.BGbpm.PMSE.Verify(buf.Bytes()[:b.VData.BGbpm.PMSEOffset()]); err != nil {
			return err
		}
	case bgheader.Version20:
		_, err := b.VData.CBNTbpm.WriteTo(buf)
		if err != nil {
			return err
		}
		if err := b.VData.CBNTbpm.PMSE.Verify(buf.Bytes()[:b.VData.CBNTbpm.KeySignatureOffset]); err != nil {
			return err
		}
	default:
		log.Error("VerifyBPM: can't identify BootGuard header")
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
	case bgheader.Version10:
		totalSize += uint32((&bgbootpolicy.BPMH{}).TotalSize())
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
		return uint16(bgbootpolicy.NewSize4K(totalSize)), nil
	case bgheader.Version20:
		totalSize += uint32(b.VData.CBNTkm.KeyManifestSignatureOffset)
		totalSize += uint32((&cbntbootpolicy.BPMH{}).TotalSize())
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
		return uint16(cbntbootpolicy.NewSize4K(totalSize)), nil
	default:
		return 0, fmt.Errorf("CalculateNEMSize: can't identify BootGuard header")
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
	case bgheader.Version10:
		hashAlg, err := bg.GetAlgFromString(hashAlgo)
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
		hStruc := bg.HashStructure{
			HashAlg: bg.Algorithm(hashAlg),
		}
		hStruc.HashBuffer = data
		b.VData.BGkm.BPKey = hStruc
	case bgheader.Version20:
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
		var keyHashes []cbntkey.Hash
		hStruc := &cbnt.HashStructure{
			HashAlg: cbnt.Algorithm(hashAlg),
		}
		hStruc.HashBuffer = data

		kH := cbntkey.Hash{
			Usage:  cbntkey.UsageBPMSigningPKD,
			Digest: *hStruc,
		}
		b.VData.CBNTkm.Hash = append(keyHashes, kH)
	default:
		log.Error("can't identify BootGuard header")
	}
	return nil
}

func (b *BootGuard) GetIBBsDigest(image []byte, hashAlgo string) (digest []byte, err error) {
	switch b.Version {
	case bgheader.Version10:
		hashAlg, err := bg.GetAlgFromString(hashAlgo)
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
	case bgheader.Version20:
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
		log.Error("can't identify BootGuard header")
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
	case bgheader.Version10:
		hashAlgo := b.VData.BGbpm.SE[0].Digest.HashAlg.String()
		d, err := b.GetIBBsDigest(data, hashAlgo)
		if err != nil {
			return fmt.Errorf("unable to getIBBsDigest for %v: %w", hashAlgo, err)
		}
		b.VData.BGbpm.SE[0].Digest.HashBuffer = make([]byte, len(d))
		copy(b.VData.BGbpm.SE[0].Digest.HashBuffer, d)
	case bgheader.Version20:
		for iterator, item := range b.VData.CBNTbpm.SE[0].DigestList.List {
			d, err := b.GetIBBsDigest(data, item.HashAlg.String())
			if err != nil {
				return fmt.Errorf("unable to getIBBsDigest for %v: %w", item.HashAlg, err)
			}
			b.VData.CBNTbpm.SE[0].DigestList.List[iterator].HashBuffer = make([]byte, len(d))
			copy(b.VData.CBNTbpm.SE[0].DigestList.List[iterator].HashBuffer, d)
		}
	default:
		log.Error("can't identify BootGuard header")
	}
	return nil
}

// BPMCryptoSecure verifies that BPM uses sane crypto algorithms
func (b *BootGuard) BPMCryptoSecure() (bool, error) {
	var errs error
	switch b.Version {
	case bgheader.Version10:
		hash := b.VData.BGbpm.SE[0].Digest.HashAlg
		if hash == bg.AlgSHA1 || hash.IsNull() {
			errs = multierr.Combine(errs, fmt.Errorf("signed IBB hash in BPM uses insecure hash algorithm SHA1 or has none"))
		}
		hash = b.VData.BGbpm.PMSE.Signature.HashAlg
		if hash == bg.AlgSHA1 || hash.IsNull() {
			errs = multierr.Combine(errs, fmt.Errorf("BPM signature uses insecure hash algorithm SHA1 or has none"))
		}
	case bgheader.Version20:
		for _, hash := range b.VData.CBNTbpm.SE[0].DigestList.List {
			if hash.HashAlg == cbnt.AlgSHA1 || hash.HashAlg.IsNull() {
				if b.VData.CBNTbpm.SE[0].DigestList.Size < 2 {
					errs = multierr.Combine(errs, fmt.Errorf("signed IBB hash list in BPM uses insecure hash algorithm SHA1 or has none"))
				}
			}
		}
		hash := b.VData.CBNTbpm.PMSE.Signature.HashAlg
		if hash == cbnt.AlgSHA1 || hash.IsNull() {
			errs = multierr.Combine(errs, fmt.Errorf("BPM signature uses insecure hash algorithm SHA1 or has none"))
		}
	}
	if errs != nil {
		return false, fmt.Errorf("%+v", errs)
	}
	return true, nil
}

// KMCryptoSecure verifies that KM uses sane crypto algorithms
func (b *BootGuard) KMCryptoSecure() (bool, error) {
	var errs error
	switch b.Version {
	case bgheader.Version10:
		hash := b.VData.BGkm.KeyAndSignature.Signature.HashAlg
		if hash == bg.AlgSHA1 || hash.IsNull() {
			errs = multierr.Combine(errs, fmt.Errorf("Key Manifest signature uses insecure hash algorithm SHA1 or has none"))
		}
		hash = b.VData.BGkm.BPKey.HashAlg
		if hash == bg.AlgSHA1 || hash.IsNull() {
			errs = multierr.Combine(errs, fmt.Errorf("signed BPM hash in Key Manifest uses insecure hash algorithm SHA1 or has none"))
		}
	case bgheader.Version20:
		hash := b.VData.CBNTkm.PubKeyHashAlg
		if hash == cbnt.AlgSHA1 || hash.IsNull() {
			errs = multierr.Combine(errs, fmt.Errorf("Key Manifest signature uses insecure hash algorithm SHA1 or has none"))
		}
		for _, hash := range b.VData.CBNTkm.Hash {
			if hash.Digest.HashAlg == cbnt.AlgSHA1 || hash.Digest.HashAlg.IsNull() {
				errs = multierr.Combine(errs, fmt.Errorf("Key Manifest hash %s uses insecure hash algorithm SHA1 or has none", hash.Usage.String()))
			}
		}
	}
	if errs != nil {
		return false, fmt.Errorf("%+v", errs)
	}
	return true, nil
}

// KMHasBPMHash verifies that KM has the correctly signed BPM hash
func (b *BootGuard) KMHasBPMHash() (bool, error) {
	var bpmHashFound bool
	switch b.Version {
	case bgheader.Version10:
		if b.VData.BGkm.BPKey.HashBufferTotalSize() > minHashTypeSize {
			bpmHashFound = true
		}
	case bgheader.Version20:
		for _, hash := range b.VData.CBNTkm.Hash {
			if hash.Usage == cbntkey.UsageBPMSigningPKD {
				bpmHashFound = true
			}
		}
	}
	if !bpmHashFound {
		return false, fmt.Errorf("couldn't find BPM hash in Key Manifest")
	}
	return true, nil
}

// BPMKeyMatchKMHash verifies that BPM pubkey hash matches KM hash of Boot Policy
func (b *BootGuard) BPMKeyMatchKMHash() (bool, error) {
	switch b.Version {
	case bgheader.Version10:
		if b.VData.BGkm.BPKey.HashBufferTotalSize() > minHashTypeSize {
			if err := b.VData.BGkm.ValidateBPMKey(b.VData.BGbpm.PMSE.KeySignature); err != nil {
				return false, fmt.Errorf("couldn't verify BPM hash in Key Manifest")
			}
		}
	case bgheader.Version20:
		for _, hash := range b.VData.CBNTkm.Hash {
			if hash.Usage == cbntkey.UsageBPMSigningPKD {
				if err := b.VData.CBNTkm.ValidateBPMKey(b.VData.CBNTbpm.PMSE.KeySignature); err != nil {
					return false, fmt.Errorf("couldn't verify BPM hash in Key Manifest")
				}
			}
		}
	}
	return true, nil
}

// StrictSaneBPMSecurityProps verifies that BPM contains security properties more strictly
func (b *BootGuard) StrictSaneBPMSecurityProps() (bool, error) {
	var errs error

	switch b.Version {
	case bgheader.Version10:
		flags := b.VData.BGbpm.SE[0].Flags
		if !flags.AuthorityMeasure() {
			errs = multierr.Append(errs, fmt.Errorf("PCR-7 data should extended for OS security"))
		}
		if !flags.TPMFailureLeavesHierarchiesEnabled() {
			errs = multierr.Append(errs, fmt.Errorf("TPM failure should lead to default measurements from PCR0 to PCR7"))
		}
	case bgheader.Version20:
		bgFlags := b.VData.CBNTbpm.SE[0].Flags
		if !bgFlags.AuthorityMeasure() {
			errs = multierr.Append(errs, fmt.Errorf("PCR-7 data should extended for OS security"))
		}
		if !bgFlags.TPMFailureLeavesHierarchiesEnabled() {
			errs = multierr.Append(errs, fmt.Errorf("TPM failure should lead to default measurements from PCR0 to PCR7"))
		}
		txtFlags := b.VData.CBNTbpm.TXTE.ControlFlags
		if txtFlags.MemoryScrubbingPolicy() != cbntbootpolicy.MemoryScrubbingPolicySACM {
			errs = multierr.Append(errs, fmt.Errorf("S-ACM memory scrubbing should be used over the BIOS"))
		}
	}
	if errs != nil {
		return false, errs
	}
	return b.SaneBPMSecurityProps()
}

// SaneBPMSecurityProps verifies that BPM contains security properties set accordingly to spec
func (b *BootGuard) SaneBPMSecurityProps() (bool, error) {
	var errs error

	switch b.Version {
	case bgheader.Version10:
		flags := b.VData.BGbpm.SE[0].Flags
		if !flags.DMAProtection() {
			errs = multierr.Combine(errs, fmt.Errorf("DMA protection should be enabled for BootGuard"))
		}
		if !flags.AuthorityMeasure() {
			return false, fmt.Errorf("PCR-7 data should be extended for OS security")
		}
		if b.VData.BGbpm.SE[0].PBETValue.PBETValue() == 0 {
			errs = multierr.Combine(errs, fmt.Errorf("firmware should not be allowed to run infinitely after incident happened"))
		}
		if len(b.VData.BGbpm.SE[0].IBBSegments) < 1 {
			return false, fmt.Errorf("no IBB segments measured")
		}
	case bgheader.Version20:
		bgFlags := b.VData.CBNTbpm.SE[0].Flags
		if !bgFlags.DMAProtection() {
			if b.VData.CBNTbpm.SE[0].DMAProtBase0 == 0 && b.VData.CBNTbpm.SE[0].VTdBAR == 0 {
				errs = multierr.Combine(errs, fmt.Errorf("DMA protection should be enabled for BootGuard"))
			}
		}
		if !bgFlags.AuthorityMeasure() {
			return false, fmt.Errorf("PCR-7 data should be extended for OS security")
		}
		if b.VData.CBNTbpm.SE[0].PBETValue.PBETValue() == 0 {
			errs = multierr.Combine(errs, fmt.Errorf("firmware should not be allowed to run infinitely after incident happened"))
		}
		pm := b.VData.BGbpm
		if pm == nil {
			errs = multierr.Combine(errs, fmt.Errorf("no BootGuard Boot Policy Manifest found"))
		}
		txtFlags := b.VData.CBNTbpm.TXTE.ControlFlags
		if !txtFlags.IsSACMRequestedToExtendStaticPCRs() {
			errs = multierr.Combine(errs, fmt.Errorf("S-ACM shall always extend static PCRs"))
		}
		if len(b.VData.CBNTbpm.SE[0].IBBSegments) < 1 {
			return false, fmt.Errorf("no IBB segments measured")
		}
	}
	if errs != nil {
		return false, fmt.Errorf("%+v", errs)
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
	case bgheader.Version10:
		if err := b.VData.BGbpm.ValidateIBB(firmware); err != nil {
			return false, fmt.Errorf("BPM final IBB hash doesn't match selected measurements in image")
		}
	case bgheader.Version20:
		if err := b.VData.CBNTbpm.ValidateIBB(firmware); err != nil {
			return false, fmt.Errorf("BPM final IBB hash doesn't match selected measurements in image")
		}
	}
	return true, nil
}

// ValidateMEAgainstManifests validates during runtime ME configuation with BootGuard KM & BPM manifests
func (b *BootGuard) ValidateMEAgainstManifests(fws *FirmwareStatus6) (bool, error) {
	var errs error
	switch b.Version {
	case bgheader.Version10:
		if fws.BPMSVN != uint32(b.VData.BGbpm.BPMSVN) {
			errs = multierr.Combine(errs, fmt.Errorf("Boot Policy Manifest SVN doesn't match ME configuration"))
		}
		if fws.KMSVN != uint32(b.VData.BGkm.KMSVN) {
			errs = multierr.Combine(errs, fmt.Errorf("Key Manifest SVN doesn't match ME configuration"))
		}
		if fws.KMID != uint32(b.VData.BGkm.KMID) {
			errs = multierr.Combine(errs, fmt.Errorf("Key Manifest ID doesn't match ME configuration"))
		}
	case bgheader.Version20:
		if fws.BPMSVN > uint32(b.VData.CBNTbpm.BPMSVN) {
			errs = multierr.Combine(errs, fmt.Errorf("Boot Policy Manifest SVN doesn't match ME configuration"))
		}
		if fws.KMSVN != uint32(b.VData.CBNTkm.KMSVN) {
			errs = multierr.Combine(errs, fmt.Errorf("Key Manifest SVN doesn't match ME configuration"))
		}
		if fws.KMID != uint32(b.VData.CBNTkm.KMID) {
			errs = multierr.Combine(errs, fmt.Errorf("Key Manifest ID doesn't match ME configuration"))
		}
	}
	if errs != nil {
		return false, fmt.Errorf("%+v", errs)
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
	defer image.Close()
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
		image.Close()
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
	case bgheader.Version10:
		b.VData.BGbpm.SE[seElement].IBBSegments = make([]bgbootpolicy.IBBSegment, len(ibbElements))
		for idx, ibb := range ibbElements {
			b.VData.BGbpm.SE[seElement].IBBSegments[idx].Base = ibb.Base
			b.VData.BGbpm.SE[seElement].IBBSegments[idx].Size = ibb.Size
			b.VData.BGbpm.SE[seElement].IBBSegments[idx].Flags = ibb.Flags
		}
	case bgheader.Version20:
		b.VData.CBNTbpm.SE[seElement].IBBSegments = make([]cbntbootpolicy.IBBSegment, len(ibbElements))
		for idx, ibb := range ibbElements {
			b.VData.CBNTbpm.SE[seElement].IBBSegments[idx].Base = ibb.Base
			b.VData.CBNTbpm.SE[seElement].IBBSegments[idx].Size = ibb.Size
			b.VData.CBNTbpm.SE[seElement].IBBSegments[idx].Flags = ibb.Flags
		}
	}
	return nil
}
