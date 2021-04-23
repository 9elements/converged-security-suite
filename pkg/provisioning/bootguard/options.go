package bootguard

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"os"

	"github.com/9elements/converged-security-suite/v2/pkg/intel/metadata/fit"
	"github.com/9elements/converged-security-suite/v2/pkg/provisioning/bootguard/bootpolicy"
	"github.com/9elements/converged-security-suite/v2/pkg/provisioning/bootguard/common"
	"github.com/9elements/converged-security-suite/v2/pkg/provisioning/bootguard/key"
	"github.com/9elements/converged-security-suite/v2/pkg/tools"
	"github.com/creasty/defaults"
	"github.com/tidwall/pretty"
)

type Options struct {
	BootPolicyManifest *bootpolicy.Manifest
	KeyManifest        *key.Manifest
}

func NewOptions() Options {
	o := Options{
		BootPolicyManifest: bootpolicy.NewManifest(),
		KeyManifest:        key.NewManifest(),
	}
	return o
}

func ParseConfig(file string) (*Options, error) {
	var bgo Options
	data, err := ioutil.ReadFile(file)
	if err != nil {
		return nil, err
	}
	if err := json.Unmarshal(data, &bgo); err != nil {
		return nil, err
	}
	return &bgo, nil
}

func setBPMHeader(bgo *Options, bpm *bootpolicy.Manifest) (*bootpolicy.BPMH, error) {
	header := bootpolicy.NewBPMH()
	if err := defaults.Set(header); err != nil {
		return nil, err
	}
	header.PMBPMVersion = bgo.BootPolicyManifest.PMBPMVersion
	header.BPMSVN = common.SVN(bgo.BootPolicyManifest.BPMH.BPMSVN)
	header.ACMSVNAuth = common.SVN(bgo.BootPolicyManifest.BPMH.ACMSVNAuth)
	header.NEMDataStack = bootpolicy.Size4K(bgo.BootPolicyManifest.BPMH.NEMDataStack)

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

func getIBBsDigest(ibbs []bootpolicy.IBBSegment, image []byte, algo common.Algorithm) ([]byte, error) {
	var hash []byte
	switch algo {
	case common.AlgSHA256:
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
	case common.AlgNull:
		return nil, nil
	default:
		return nil, fmt.Errorf("couldn't match requested hash algorithm: 0x%x", algo)
	}
	return hash, nil
}

func setPMElement(bgo *Options) (*bootpolicy.PM, error) {
	pme := bootpolicy.NewPM()
	if bgo.BootPolicyManifest.PME == nil {
		return nil, nil
	}
	pme.Data = bgo.BootPolicyManifest.PME.Data
	return pme, nil
}

func setPMSElement(bgo *Options, bpm *bootpolicy.Manifest) (*bootpolicy.Signature, error) {
	psme := bootpolicy.NewSignature()
	return psme, nil
}

// SetKM takes Options struct and initializes a new KM with the given configuration.
func SetKM(bgo *Options) (*key.Manifest, error) {
	km := key.NewManifest()
	km = bgo.KeyManifest
	return km, nil
}

func setIBBSegment(bgo *Options, image []byte) (*bootpolicy.SE, error) {
	d, err := getIBBsDigest(bgo.BootPolicyManifest.SE[0].IBBSegments, image, common.AlgSHA256)
	if err != nil {
		return nil, err
	}
	bgo.BootPolicyManifest.SE[0].Digest.HashBuffer = make([]byte, len(d))
	copy(bgo.BootPolicyManifest.SE[0].Digest.HashBuffer, d)

	return &bgo.BootPolicyManifest.SE[0], nil
}

// GenerateBPM generates a Boot Policy Manifest with the given config and firmware image
func GenerateBPM(bgo *Options, biosFilepath string) (*bootpolicy.Manifest, error) {
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

// ReadConfigFromBIOSImage reads boot guard options, boot policy manifest and key manifest from a given firmware image
// and writes that to a given file in json format
func ReadConfigFromBIOSImage(biosFilepath string, configFilepath *os.File) (*Options, error) {
	bgo := NewOptions()
	bios, err := ioutil.ReadFile(biosFilepath)
	if err != nil {
		return nil, err
	}
	bpmEntry, kmEntry, _, err := ParseFITEntries(bios)
	if err != nil {
		return nil, err
	}

	bgo.BootPolicyManifest, err = bpmEntry.ParseDataBG()
	if err != nil {
		return nil, fmt.Errorf("ReadConfigurationFromBIOSImage: unable to get BPM: %w", err)
	}

	bgo.KeyManifest, err = kmEntry.ParseDataBG()
	if err != nil {
		return nil, fmt.Errorf("ReadConfigurationFromBIOSImage: unable to get KM: %w", err)
	}

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

// ParseFITEntries takes a firmware image and extract Boot policy manifest, key manifest and acm information.
func ParseFITEntries(image []byte) (bpm *fit.EntryBootPolicyManifestRecord, km *fit.EntryKeyManifestRecord, acm *fit.EntrySACM, err error) {
	fitTable, err := fit.GetTable(image)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("unable to get FIT: %w", err)
	}
	fitEntries := fitTable.GetEntries(image)
	for _, entry := range fitEntries {
		switch entry := entry.(type) {
		case *fit.EntryBootPolicyManifestRecord:
			bpm = entry
		case *fit.EntryKeyManifestRecord:
			km = entry
		case *fit.EntrySACM:
			acm = entry
		}
	}
	if bpm == nil || km == nil || acm == nil {
		return nil, nil, nil, fmt.Errorf("image has no BPM (isNil:%v) or/and KM (isNil:%v) or/and ACM (isNil:%v)", bpm == nil, km == nil, acm == nil)
	}
	return bpm, km, acm, nil
}

// GetBPMPubHash takes the path to public BPM signing key and hash algorithm
// and returns a hash with hashAlg of pub BPM singing key
func GetBPMPubHash(path string) (*common.HashStructure, error) {
	var data []byte
	pubkey, err := ReadPubKey(path)
	if err != nil {
		return nil, err
	}
	hash, err := common.AlgSHA256.Hash()
	if err != nil {
		return nil, err
	}
	var kAs common.Key
	if err := kAs.SetPubKey(pubkey); err != nil {
		return nil, err
	}
	k := kAs.Data[4:]
	if _, err := hash.Write(k); err != nil {
		return nil, err
	}
	data = hash.Sum(nil)
	hStruc := common.HashStructure{
		HashAlg: common.AlgSHA256,
	}
	hStruc.HashBuffer = data

	return &hStruc, nil
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
