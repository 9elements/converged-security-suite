package bg

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

	"github.com/google/go-tpm/tpm2"

	"github.com/9elements/converged-security-suite/v2/pkg/intel/metadata/manifest"
	"github.com/9elements/converged-security-suite/v2/pkg/intel/metadata/manifest/bootpolicy"
	"github.com/9elements/converged-security-suite/v2/pkg/intel/metadata/manifest/key"
	"github.com/9elements/converged-security-suite/v2/pkg/tools"
	"github.com/creasty/defaults"
	"github.com/tidwall/pretty"
)

// IbbSegments exports the struct of IBB Segments
type IbbSegment struct {
	Offset uint32 `json:"offset"` //
	Size   uint32 `json:"size"`   //
	Flags  uint16 `json:"flags"`  //
}

// KeyHash export for usage as cmd line argument type
type KeyHash struct {
	Usage     uint64         `json:"usage"`     //
	Hash      string         `json:"hash"`      //
	Algorithm tpm2.Algorithm `json:"algorithm"` //
}

// TODO: remove this structure, it could be replaced with something like:
//           type BootGuardOptions struct {
//		         BPM *bootpolicy.Manifest
//               KM *key.Manifest
//           }
//       It will also remove a lot of extra code.

// BootGuardOptions presents all available options for BootGuard configuarion file.
type BootGuardOptions struct {
	BootPolicyManifest bootpolicy.Manifest
	KeyManifest        key.Manifest
}

// ParseConfig parses a boot guard option json file
func ParseConfig(filepath string) (*BootGuardOptions, error) {
	var bgo BootGuardOptions
	data, err := ioutil.ReadFile(filepath)
	if err != nil {
		return nil, err
	}
	if err = json.Unmarshal(data, &bgo); err != nil {
		return nil, err
	}
	return &bgo, nil
}

func setBPMHeader(bgo *BootGuardOptions, bpm *bootpolicy.Manifest) (*bootpolicy.BPMH, error) {
	header := bootpolicy.NewBPMH()
	if err := defaults.Set(header); err != nil {
		return nil, err
	}
	header.BPMRevision = bgo.BootPolicyManifest.BPMRevision
	header.BPMSVN = manifest.SVN(bgo.BootPolicyManifest.BPMH.BPMSVN)
	header.ACMSVNAuth = manifest.SVN(bgo.BootPolicyManifest.BPMH.ACMSVNAuth)
	header.NEMDataStack = bootpolicy.Size4K(bgo.BootPolicyManifest.BPMH.NEMDataStack)
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

func getIBBsDigest(ibbs []bootpolicy.IBBSegment, image []byte, algo tpm2.Algorithm) ([]byte, error) {
	var hash []byte
	switch algo {
	case tpm2.AlgSHA1:
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
	case tpm2.AlgSHA256:
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
	case tpm2.AlgSHA384:
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
	case tpm2.AlgSHA512:
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
	case tpm2.AlgNull:
		return nil, nil
	default:
		return nil, fmt.Errorf("couldn't match requested hash algorithm: 0x%x", algo)
	}
	return hash, nil
}

func setIBBSegment(bgo *BootGuardOptions, image []byte) (*bootpolicy.SE, error) {
	for iterator, item := range bgo.BootPolicyManifest.SE[0].DigestList.List {
		d, err := getIBBsDigest(bgo.BootPolicyManifest.SE[0].IBBSegments, image, item.HashAlg)
		if err != nil {
			return nil, err
		}
		bgo.BootPolicyManifest.SE[0].DigestList.List[iterator].HashBuffer = make([]byte, len(d))
		copy(bgo.BootPolicyManifest.SE[0].DigestList.List[iterator].HashBuffer, d)
	}

	return &bgo.BootPolicyManifest.SE[0], nil
}

func setTXTElement(bgo *BootGuardOptions) (*bootpolicy.TXT, error) {
	txte := bootpolicy.NewTXT()
	txte = bgo.BootPolicyManifest.TXTE
	return txte, nil
}

func setPCDElement(bgo *BootGuardOptions) (*bootpolicy.PCD, error) {
	pcde := bootpolicy.NewPCD()
	if bgo.BootPolicyManifest.PCDE == nil {
		return nil, nil
	}
	pcde.Data = bgo.BootPolicyManifest.PCDE.Data
	return pcde, nil
}

func setPMElement(bgo *BootGuardOptions) (*bootpolicy.PM, error) {
	pme := bootpolicy.NewPM()
	if bgo.BootPolicyManifest.PME == nil {
		return nil, nil
	}
	pme.Data = bgo.BootPolicyManifest.PME.Data
	return pme, nil
}

func setPMSElement(bgo *BootGuardOptions, bpm *bootpolicy.Manifest) (*bootpolicy.Signature, error) {
	psme := bootpolicy.NewSignature()
	return psme, nil
}

// SetKM takes BootGuardOptiones struct and initializes a new KM with the given configuration.
func SetKM(bgo *BootGuardOptions) (*key.Manifest, error) {
	km := key.NewManifest()
	km = &bgo.KeyManifest
	return km, nil
}

// GenerateBPM generates a Boot Policy Manifest with the given config and firmware image
func GenerateBPM(bgo *BootGuardOptions, biosFilepath string) (*bootpolicy.Manifest, error) {
	bpm := bootpolicy.NewManifest()
	data, err := ioutil.ReadFile(biosFilepath)
	if err != nil {
		return nil, err
	}
	se, err := setIBBSegment(bgo, data)
	if err != nil {
		return nil, err
	}
	bpm.SE = append(bpm.SE, *se)
	bpm.TXTE, err = setTXTElement(bgo)
	if err != nil {
		return nil, err
	}
	bpm.PCDE, err = setPCDElement(bgo)
	if err != nil {
		return nil, err
	}
	bpm.PME, err = setPMElement(bgo)
	if err != nil {
		return nil, err
	}
	bpmh, err := setBPMHeader(bgo, bpm)
	if err != nil {
		return nil, err
	}
	bpm.BPMH = *bpmh
	pmse, err := setPMSElement(bgo, bpm)
	if err != nil {
		return nil, err
	}
	bpm.PMSE = *pmse

	return bpm, nil
}

// CreateManifests takes a boot guard options configuration file in json format and a firmware image and extracts km and bpm
func CreateManifests(configFilepath, biosFilepath string) (*bootpolicy.Manifest, *key.Manifest, error) {
	bpm := bootpolicy.NewManifest()
	bgo, err := ParseConfig(configFilepath)
	if err != nil {
		return nil, nil, err
	}
	data, err := ioutil.ReadFile(biosFilepath)
	if err != nil {
		return nil, nil, err
	}
	_, _, acmBuf, err := ParseFITEntries(data)
	if err != nil {
		return nil, nil, err
	}
	acm, _, _, _, err, err2 := tools.ParseACM(acmBuf)
	if err != nil {
		return nil, nil, err
	}
	if err2 != nil {
		return nil, nil, err
	}
	se, err := setIBBSegment(bgo, data)
	if err != nil {
		return nil, nil, err
	}
	bpm.SE = append(bpm.SE, *se)
	bpm.TXTE, err = setTXTElement(bgo)
	if err != nil {
		return nil, nil, err
	}
	bpm.PCDE, err = setPCDElement(bgo)
	if err != nil {
		return nil, nil, err
	}
	bpm.PME, err = setPMElement(bgo)
	if err != nil {
		return nil, nil, err
	}
	bpmh, err := setBPMHeader(bgo, bpm)
	if err != nil {
		return nil, nil, err
	}
	bpm.BPMH = *bpmh
	pmse, err := setPMSElement(bgo, bpm)
	if err != nil {
		return nil, nil, err
	}
	bpm.PMSE = *pmse
	km, err := SetKM(bgo)
	if err != nil {
		return nil, nil, err
	}
	if bgo.BootPolicyManifest.NEMDataStack <= 0 {
		bpm.BPMH.NEMDataStack, err = CalculateNEMSize(data, bpm, km, acm)
		if err != nil {
			return nil, nil, err
		}
	}
	bpm.RehashRecursive()
	km.RehashRecursive()
	return bpm, km, nil
}

// WriteConfig writes a BootGuard config file to the given path with given options.
func WriteConfig(f *os.File, bgo *BootGuardOptions) error {
	cfg, err := json.Marshal(bgo)
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
func ReadConfigFromBIOSImage(biosFilepath string, configFilepath *os.File) (*BootGuardOptions, error) {
	var bgo BootGuardOptions
	var bpm *bootpolicy.Manifest
	var km *key.Manifest
	bios, err := ioutil.ReadFile(biosFilepath)
	if err != nil {
		return nil, err
	}
	bpmBuf, kmBuf, _, err := ParseFITEntries(bios)
	if err != nil {
		return nil, err
	}

	if len(bpmBuf) == 0 {
		return nil, fmt.Errorf("ReadConfigurationFromBIOSImage: No BPM found to read config from")
	}

	reader := bytes.NewReader(bpmBuf)
	bpm, err = ParseBPM(reader)
	if err != nil {
		return nil, err
	}

	if len(kmBuf) == 0 {
		return nil, fmt.Errorf("ReadConfigurationFromBIOSImage: No KM found to read config from")
	}

	reader = bytes.NewReader(kmBuf)
	km, err = ParseKM(reader)
	if err != nil {
		return nil, err
	}
	/* Boot Policy Manifest */
	// BPMH
	bgo.BootPolicyManifest = *bpm

	/* Key Manifest */
	bgo.KeyManifest = *km
	data, err := json.Marshal(bgo)
	if err != nil {
		return nil, err
	}
	json := pretty.Pretty(data)
	if _, err = configFilepath.Write(json); err != nil {
		return nil, err
	}
	return &bgo, nil
}

// GetBPMPubHash takes the path to public BPM signing key and hash algorithm
// and returns a hash with hashAlg of pub BPM singing key
func GetBPMPubHash(path string, hashAlg tpm2.Algorithm) ([]key.Hash, error) {
	var data []byte
	pubkey, err := ReadPubKey(path)
	if err != nil {
		return nil, err
	}
	alg, err := hashAlg.Hash()
	if err != nil {
		return nil, err
	}
	hash := alg.New()
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
		HashAlg: tpm2.Algorithm(hashAlg),
	}
	copy(hStruc.HashBuffer, data)

	kH := key.Hash{
		Usage:  key.UsageBPMSigningPKD,
		Digest: *hStruc,
	}
	keyHashes = append(keyHashes, kH)
	return keyHashes, nil
}
