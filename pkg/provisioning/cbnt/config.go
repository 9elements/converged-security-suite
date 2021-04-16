package cbnt

import (
	"bytes"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"os"

	"github.com/9elements/converged-security-suite/v2/pkg/intel/metadata/manifest"
	"github.com/9elements/converged-security-suite/v2/pkg/intel/metadata/manifest/bootpolicy"
	"github.com/9elements/converged-security-suite/v2/pkg/intel/metadata/manifest/key"
	"github.com/9elements/converged-security-suite/v2/pkg/tools"
	"github.com/creasty/defaults"
	"github.com/tidwall/pretty"
	"github.com/tjfoc/gmsm/sm3"
)

// IbbSegment exports the struct of IBB Segments
type IbbSegment struct {
	Offset uint32 `json:"offset"` //
	Size   uint32 `json:"size"`   //
	Flags  uint16 `json:"flags"`  //
}

// KeyHash export for usage as cmd line argument type
type KeyHash struct {
	Usage     uint64             `json:"usage"`     //
	Hash      string             `json:"hash"`      //
	Algorithm manifest.Algorithm `json:"algorithm"` //
}

// Options presents all available options for CBnT configuarion file.
type Options struct {
	BootPolicyManifest *bootpolicy.Manifest
	KeyManifest        *key.Manifest
}

// ParseConfig parses a boot guard option json file
func ParseConfig(filepath string) (*Options, error) {
	var cbnto Options
	data, err := ioutil.ReadFile(filepath)
	if err != nil {
		return nil, err
	}
	if err = json.Unmarshal(data, &cbnto); err != nil {
		return nil, err
	}
	return &cbnto, nil
}

func setBPMHeader(cbnto *Options, bpm *bootpolicy.Manifest) (*bootpolicy.BPMH, error) {
	header := bootpolicy.NewBPMH()
	if err := defaults.Set(header); err != nil {
		return nil, err
	}
	header.BPMRevision = cbnto.BootPolicyManifest.BPMRevision
	header.BPMSVN = manifest.SVN(cbnto.BootPolicyManifest.BPMH.BPMSVN)
	header.ACMSVNAuth = manifest.SVN(cbnto.BootPolicyManifest.BPMH.ACMSVNAuth)
	header.NEMDataStack = bootpolicy.Size4K(cbnto.BootPolicyManifest.BPMH.NEMDataStack)
	header.KeySignatureOffset = uint16(bpm.PMSEOffset() + bpm.PMSE.KeySignatureOffset())

	return header, nil
}

func getIBBSegment(ibbs []bootpolicy.IBBSegment, image []byte) ([][]byte, error) {
	reader := bytes.NewReader(image)
	ibbSegments := make([][]byte, len(ibbs))
	for idx, ibb := range ibbs {
		if ibb.Flags&(1<<0) != 0 {
			continue
		}
		//offset := uint64(ibb.BaseOffset())
		addr, err := tools.CalcImageOffset(image, uint64(ibb.Base))
		if err != nil {
			return nil, err
		}
		_, err = reader.Seek(int64(addr), io.SeekStart)
		if err != nil {
			return nil, err
		}
		size := uint64(ibb.Size)
		ibbSegments[idx] = make([]byte, size)
		_, err = reader.Read(ibbSegments[idx])
		if err != nil {
			return nil, err
		}
	}
	return ibbSegments, nil
}

func getIBBsDigest(ibbs []bootpolicy.IBBSegment, image []byte, algo manifest.Algorithm) ([]byte, error) {
	var hash []byte
	switch algo {
	case manifest.AlgSHA1:
		h := sha1.New()
		segments, err := getIBBSegment(ibbs, image)
		if err != nil {
			return nil, err
		}
		for _, segment := range segments {
			_, err = h.Write(segment)
			if err != nil {
				return nil, err
			}
		}
		hash = h.Sum(nil)
	case manifest.AlgSHA256:
		h := sha256.New()
		segments, err := getIBBSegment(ibbs, image)
		if err != nil {
			return nil, err
		}
		for _, segment := range segments {
			_, err = h.Write(segment)
			if err != nil {
				return nil, err
			}
		}
		hash = h.Sum(nil)
	case manifest.AlgSHA384:
		h := sha512.New384()
		segments, err := getIBBSegment(ibbs, image)
		if err != nil {
			return nil, err
		}
		for _, segment := range segments {
			_, err = h.Write(segment)
			if err != nil {
				return nil, err
			}
		}
		hash = h.Sum(nil)
	case manifest.AlgSHA512:
		h := sha512.New512_256()
		segments, err := getIBBSegment(ibbs, image)
		if err != nil {
			return nil, err
		}
		for _, segment := range segments {
			_, err = h.Write(segment)
			if err != nil {
				return nil, err
			}
		}
		hash = h.Sum(nil)
	case manifest.AlgSM3_256:
		h := sm3.New()
		segments, err := getIBBSegment(ibbs, image)
		if err != nil {
			return nil, err
		}
		for _, segment := range segments {
			_, err = h.Write(segment)
			if err != nil {
				return nil, err
			}
		}
		hash = h.Sum(nil)
	case manifest.AlgNull:
		return nil, nil
	default:
		return nil, fmt.Errorf("couldn't match requested hash algorithm: 0x%x", algo)
	}
	return hash, nil
}

func setIBBSegment(cbnto *Options, image []byte) (*bootpolicy.SE, error) {
	for iterator, item := range cbnto.BootPolicyManifest.SE[0].DigestList.List {
		d, err := getIBBsDigest(cbnto.BootPolicyManifest.SE[0].IBBSegments, image, item.HashAlg)
		if err != nil {
			return nil, err
		}
		cbnto.BootPolicyManifest.SE[0].DigestList.List[iterator].HashBuffer = make([]byte, len(d))
		copy(cbnto.BootPolicyManifest.SE[0].DigestList.List[iterator].HashBuffer, d)
	}

	return &cbnto.BootPolicyManifest.SE[0], nil
}

func setTXTElement(cbnto *Options) (*bootpolicy.TXT, error) {
	txte := bootpolicy.NewTXT()
	txte = cbnto.BootPolicyManifest.TXTE
	return txte, nil
}

func setPCDElement(cbnto *Options) (*bootpolicy.PCD, error) {
	pcde := bootpolicy.NewPCD()
	if cbnto.BootPolicyManifest.PCDE == nil {
		return nil, nil
	}
	pcde.Data = cbnto.BootPolicyManifest.PCDE.Data
	return pcde, nil
}

func setPMElement(cbnto *Options) (*bootpolicy.PM, error) {
	pme := bootpolicy.NewPM()
	if cbnto.BootPolicyManifest.PME == nil {
		return nil, nil
	}
	pme.Data = cbnto.BootPolicyManifest.PME.Data
	return pme, nil
}

func setPMSElement(cbnto *Options, bpm *bootpolicy.Manifest) (*bootpolicy.Signature, error) {
	psme := bootpolicy.NewSignature()
	return psme, nil
}

// SetKM takes Options struct and initializes a new KM with the given configuration.
func SetKM(cbnto *Options) (*key.Manifest, error) {
	km := key.NewManifest()
	km = cbnto.KeyManifest
	return km, nil
}

// GenerateBPM generates a Boot Policy Manifest with the given config and firmware image
func GenerateBPM(cbnto *Options, biosFilepath string) (*bootpolicy.Manifest, error) {
	bpm := bootpolicy.NewManifest()
	data, err := ioutil.ReadFile(biosFilepath)
	if err != nil {
		return nil, err
	}
	se, err := setIBBSegment(cbnto, data)
	if err != nil {
		return nil, err
	}
	bpm.SE = append(bpm.SE, *se)
	bpm.TXTE, err = setTXTElement(cbnto)
	if err != nil {
		return nil, err
	}
	bpm.PCDE, err = setPCDElement(cbnto)
	if err != nil {
		return nil, err
	}
	bpm.PME, err = setPMElement(cbnto)
	if err != nil {
		return nil, err
	}
	bpmh, err := setBPMHeader(cbnto, bpm)
	if err != nil {
		return nil, err
	}
	bpm.BPMH = *bpmh
	pmse, err := setPMSElement(cbnto, bpm)
	if err != nil {
		return nil, err
	}
	bpm.PMSE = *pmse

	return bpm, nil
}

// WriteConfig writes a CBnT config file to the given path with given options.
func WriteConfig(f *os.File, cbnto *Options) error {
	cfg, err := json.Marshal(cbnto)
	if err != nil {
		return err
	}
	json := pretty.Pretty(cfg)
	if _, err := f.Write(json); err != nil {
		return err
	}
	return nil
}

// ReadConfigFromBIOSImage reads boot guard options, boot policy manifest and key manifest from a given firmware image
// and writes that to a given file in json format
func ReadConfigFromBIOSImage(biosFilepath string, configFilepath *os.File) (*Options, error) {
	var cbnto Options
	var bpm *bootpolicy.Manifest
	var km *key.Manifest
	bios, err := ioutil.ReadFile(biosFilepath)
	if err != nil {
		return nil, err
	}
	bpmEntry, kmEntry, _, err := ParseFITEntries(bios)
	if err != nil {
		return nil, err
	}

	bpm, err = bpmEntry.ParseData()
	if err != nil {
		return nil, fmt.Errorf("ReadConfigurationFromBIOSImage: unable to get BPM: %w", err)
	}

	km, err = kmEntry.ParseData()
	if err != nil {
		return nil, fmt.Errorf("ReadConfigurationFromBIOSImage: unable to get KM: %w", err)
	}

	/* Boot Policy Manifest */
	// BPMH
	cbnto.BootPolicyManifest = bpm

	/* Key Manifest */
	cbnto.KeyManifest = km
	data, err := json.Marshal(cbnto)
	if err != nil {
		return nil, err
	}
	json := pretty.Pretty(data)
	if _, err = configFilepath.Write(json); err != nil {
		return nil, err
	}
	return &cbnto, nil
}

// GetBPMPubHash takes the path to public BPM signing key and hash algorithm
// and returns a hash with hashAlg of pub BPM singing key
func GetBPMPubHash(path string, hashAlg manifest.Algorithm) ([]key.Hash, error) {
	var data []byte
	pubkey, err := ReadPubKey(path)
	if err != nil {
		return nil, err
	}
	hash, err := hashAlg.Hash()
	if err != nil {
		return nil, err
	}
	var kAs manifest.Key
	if err := kAs.SetPubKey(pubkey); err != nil {
		return nil, err
	}
	k := kAs.Data[4:]
	if _, err := hash.Write(k); err != nil {
		return nil, err
	}
	data = hash.Sum(nil)
	var keyHashes []key.Hash
	hStruc := &manifest.HashStructure{
		HashAlg: manifest.Algorithm(hashAlg),
	}
	hStruc.HashBuffer = data

	kH := key.Hash{
		Usage:  key.UsageBPMSigningPKD,
		Digest: *hStruc,
	}
	keyHashes = append(keyHashes, kH)
	return keyHashes, nil
}
