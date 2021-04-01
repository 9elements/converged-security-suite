package main

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"os"

	"github.com/linuxboot/fiano/pkg/uefi"

	"github.com/9elements/converged-security-suite/v2/pkg/intel/metadata/manifest"
	"github.com/9elements/converged-security-suite/v2/pkg/intel/metadata/manifest/bootpolicy"
	"github.com/9elements/converged-security-suite/v2/pkg/intel/metadata/manifest/key"
	"github.com/9elements/converged-security-suite/v2/pkg/provisioning/bg"
	"github.com/9elements/converged-security-suite/v2/pkg/tools"
)

type context struct {
	Debug bool
}

type versionCmd struct {
}

type templateCmd struct {
	Path string `arg required name:"path" help:"Path to the newly generated JSON configuration file." type:"path"`
	//BootGuard Manifest Header args
	Revision uint8             `flag optional name:"revision" help:"Platform Manufacturer’s BPM revision number."`
	SVN      manifest.SVN      `flag optional name:"svn" help:"Boot Policy Manifest Security Version Number"`
	ACMSVN   manifest.SVN      `flag optional name:"acmsvn" help:"Authorized ACM Security Version Number"`
	NEMS     bootpolicy.Size4K `flag optional name:"nems" help:"Size of data region need by IBB expressed in 4K pages. E.g., value of 1 = 4096 bytes; 2 = 8092 bytes, etc. Must not be zero"`
	// IBB args
	PBET        bootpolicy.PBETValue `flag optional name:"pbet" help:"Protect BIOS Environment Timer (PBET) value."`
	IBBSegFlags bootpolicy.SEFlags   `flag optional name:"ibbflags" help:"IBB Control flags"`
	MCHBAR      uint64               `flag optional name:"mchbar" help:"MCHBAR address"`
	VDTBAR      uint64               `flag optional name:"vdtbar" help:"VTDPVC0BAR address"`
	DMABase0    uint32               `flag optional name:"dmabase0" help:"Low DMA protected range base"`
	DMASize0    uint32               `flag optional name:"dmasize0" help:"Low DMA protected range limit"`
	DMABase1    uint64               `flag optional name:"dmabase1" help:"High DMA protected range base."`
	DMASize1    uint64               `flag optional name:"dmasize1" help:"High DMA protected range limit."`
	EntryPoint  uint32               `flag optional name:"entrypoint" help:"IBB (Startup BIOS) entry point"`
	IbbHash     []manifest.Algorithm `flag optional name:"ibbhash" help:"IBB Hash Algorithm"`
	IbbSegbase  uint32               `flag optional name:"ibbsegbase" help:"Value for IbbSegment structure"`
	IbbSegsize  uint32               `flag optional name:"ibbsegsize" help:"Value for IBB segment structure"`
	IbbSegFlag  uint16               `flag optional name:"ibbsegflag" help:"Reducted"`
	// TXT args
	SintMin           uint8                       `flag optional name:"sintmin" help:"OEM authorized SinitMinSvn value"`
	TXTFlags          bootpolicy.TXTControlFlags  `flag optional name:"txtflags" help:"TXT Element control flags"`
	PowerDownInterval bootpolicy.Duration16In5Sec `flag optional name:"powerdowninterval" help:"Duration of Power Down in 5 sec increments"`
	ACPIBaseOffset    uint16                      `flag optional name:"acpibaseoffset" help:"ACPI IO offset."`
	PowermBaseOffset  uint32                      `flag optional name:"powermbaseoffset" help:"ACPI MMIO offset."`
	CMOSOff0          uint8                       `flag optional name:"cmosoff0" help:"CMOS byte in bank 0 to store platform wakeup time"`
	CMOSOff1          uint8                       `flag optional name:"cmosoff1" help:"Second CMOS byte in bank 0 to store platform wakeup time"`
}

type kmPrintCmd struct {
	Path string `arg required name:"path" help:"Path to the Key Manifest binary file." type:"path"`
}

type bpmPrintCmd struct {
	Path string `arg required name:"path" help:"Path to the Boot Policy Manifest binary file." type:"path"`
}

type acmPrintCmd struct {
	Path string `arg required name:"path" help:"Path to the ACM binary file." type:"path"`
}

type biosPrintCmd struct {
	Path string `arg required name:"path" help:"Path to the full BIOS binary file." type:"path"`
}

type acmExportCmd struct {
	BIOS string `arg required name:"bios" help:"Path to the full BIOS binary file." type:"path"`
	Out  string `arg required name:"out" help:"Path to the newly generated ACM binary file." type:"path"`
}

type kmExportCmd struct {
	BIOS string `arg required name:"bios" help:"Path to the full BIOS binary file." type:"path"`
	Out  string `arg required name:"out" help:"Path to the newly generated KM binary file." type:"path"`
}

type bpmExportCmd struct {
	BIOS string `arg required name:"bios" help:"Path to the full BIOS binary file." type:"path"`
	Out  string `arg required name:"out" help:"Path to the newly generated BPM binary file." type:"path"`
}

type generateKMCmd struct {
	KM         string             `arg required name:"km" help:"Path to the newly generated Key Manifest binary file." type:"path"`
	Key        string             `arg required name:"key" help:"Public signing key"`
	Config     string             `flag optional name:"config" help:"Path to the JSON config file." type:"path"`
	Revision   uint8              `flag optional name:"revision" help:"Platform Manufacturer’s BPM revision number."`
	SVN        manifest.SVN       `flag optional name:"svn" help:"Boot Policy Manifest Security Version Number"`
	ID         uint8              `flag optional name:"id" help:"The key Manifest Identifier"`
	PKHashAlg  manifest.Algorithm `flag optional name:"pkhashalg" help:"Hash algorithm of OEM public key digest"`
	KMHashes   []key.Hash         `flag optional name:"kmhashes" help:"Key hashes for BPM, ACM, uCode etc"`
	BpmPubkey  string             `flag optional name:"bpmpubkey" help:"Path to bpm public signing key"`
	BpmHashAlg manifest.Algorithm `flag optional name:"bpmhashalgo" help:"Hash algorithm for bpm public signing key"`
	Out        string             `flag optional name:"out" help:"Path to write applied config to"`
	Cut        bool               `flag optional name:"cut" help:"Cuts the signature before writing to binary."`
	PrintME    bool               `flag optional name:"printme" help:"Prints the hash of KM public signing key"`
}

type generateBPMCmd struct {
	BPM    string `arg required name:"bpm" help:"Path to the newly generated Boot Policy Manifest binary file." type:"path"`
	BIOS   string `arg required name:"bios" help:"Path to the full BIOS binary file." type:"path"`
	Config string `flag optional name:"config" help:"Path to the JSON config file." type:"path"`
	//BootGuard Manifest Header args
	Revision uint8             `flag optional name:"revision" help:"Platform Manufacturer’s BPM revision number."`
	SVN      manifest.SVN      `flag optional name:"svn" help:"Boot Policy Manifest Security Version Number"`
	ACMSVN   manifest.SVN      `flag optional name:"acmsvn" help:"Authorized ACM Security Version Number"`
	NEMS     bootpolicy.Size4K `flag optional name:"nems" help:"Size of data region need by IBB expressed in 4K pages. E.g., value of 1 = 4096 bytes; 2 = 8092 bytes, etc. Must not be zero"`
	// IBB args
	PBET        bootpolicy.PBETValue `flag optional name:"pbet" help:"Protect BIOS Environment Timer (PBET) value."`
	IBBSegFlags bootpolicy.SEFlags   `flag optional name:"ibbflags" help:"IBB Control flags"`
	MCHBAR      uint64               `flag optional name:"mchbar" help:"MCHBAR address"`
	VDTBAR      uint64               `flag optional name:"vdtbar" help:"VTDPVC0BAR address"`
	DMABase0    uint32               `flag optional name:"dmabase0" help:"Low DMA protected range base"`
	DMASize0    uint32               `flag optional name:"dmasize0" help:"Low DMA protected range limit"`
	DMABase1    uint64               `flag optional name:"dmabase1" help:"High DMA protected range base."`
	DMASize1    uint64               `flag optional name:"dmasize1" help:"High DMA protected range limit."`
	EntryPoint  uint32               `flag optional name:"entrypoint" help:"IBB (Startup BIOS) entry point"`
	IbbHash     []manifest.Algorithm `flag optional name:"ibbhash" help:"IBB Hash Algorithm"`
	IbbSegbase  uint32               `flag optional name:"ibbsegbase" help:"Value for IbbSegment structure"`
	IbbSegsize  uint32               `flag optional name:"ibbsegsize" help:"Value for IBB segment structure"`
	IbbSegFlag  uint16               `flag optional name:"ibbsegflag" help:"Reducted"`
	// TXT args
	SintMin           uint8                       `flag optional name:"sintmin" help:"OEM authorized SinitMinSvn value"`
	TXTFlags          bootpolicy.TXTControlFlags  `flag optional name:"txtflags" help:"TXT Element control flags"`
	PowerDownInterval bootpolicy.Duration16In5Sec `flag optional name:"powerdowninterval" help:"Duration of Power Down in 5 sec increments"`
	ACPIBaseOffset    uint16                      `flag optional name:"acpibaseoffset" help:"ACPI IO offset."`
	PowermBaseOffset  uint32                      `flag optional name:"powermbaseoffset" help:"ACPI MMIO offset."`
	CMOSOff0          uint8                       `flag optional name:"cmosoff0" help:"CMOS byte in bank 0 to store platform wakeup time"`
	CMOSOff1          uint8                       `flag optional name:"cmosoff1" help:"Second CMOS byte in bank 0 to store platform wakeup time"`

	Out string `flag optional name:"out" help:"Path to write applied config to"`
	Cut bool   `flag optional name:"cut" help:"Cuts the signature before writing to binary."`
}

type signKMCmd struct {
	KmIn     string `arg required name:"kmin" help:"Path to the generated Key Manifest binary file." type:"path"`
	KmOut    string `arg required name:"kmout" help:"Path to write the signed KM to"`
	Key      string `arg required name:"km-keyfile" help:"Path to the encrypted PKCS8 private key file." type:"path"`
	Password string `arg required name:"password" help:"Password to decrypted PKCS8 private key file"`
}

type signBPMCmd struct {
	BpmIn    string `arg required name:"bpmin" help:"Path to the newly generated Boot Policy Manifest binary file." type:"path"`
	BpmOut   string `arg required name."bpmout" help:"Path to write the signed BPM to"`
	Key      string `arg required name:"bpm-keyfile" help:"Path to the encrypted PKCS8 private key file." type:"path"`
	Password string `arg required name:"password" help:"Password to decrypt PKCS8 private key file"`
}

type readConfigCmd struct {
	Config string `arg required name:"config" help:"Path to the JSON config file." type:"path"`
	BIOS   string `arg required name:"bios" help:"Path to the full BIOS binary file." type:"path"`
}

type stitchingKMCmd struct {
	KM        string `arg required name:"km" help:"Path to the Key Manifest binary file." type:"path"`
	Signature string `arg required name:"signature" help:"Path to the Key Manifest signature file." type:"path"`
	PubKey    string `arg required name:"pubkey" help:"Path to the Key Manifest public key file." type:"path"`
	Out       string `arg required name:"out" help:"Path to the newly stitched KM binary file." type:"path"`
}

type stitchingBPMCmd struct {
	BPM       string `arg required name:"bpm" help:"Path to the Boot Policy Manifest binary file." type:"path"`
	Signature string `arg required name:"signature" help:"Path to the Boot Policy Manifest signature file." type:"path"`
	PubKey    string `arg required name:"pubkey" help:"Path to the Boot Policy Manifest public key file." type:"path"`
	Out       string `arg required name:"out" help:"Path to the newly stitched BPM binary file." type:"path"`
}

type stitchingCmd struct {
	BIOS string `arg required name:"bios" help:"Path to the full BIOS binary file." type:"path"`
	ACM  string `flag optional name:"acm" help:"Path to the ACM binary file." type:"path"`
	KM   string `flag optional name:"km" help:"Path to the Key Manifest binary file." type:"path"`
	BPM  string `flag optional name:"bpm" help:"Path to the Boot Policy Manifest binary file." type:"path"`
	ME   string `flag optional name:"me" help:"Path to the Management Engine binary file." type:"path"`
}

type keygenCmd struct {
	Algo     string `arg require name:"algo" help:"Select crypto algorithm for key generation. Options: RSA2048. RSA3072, ECC224, ECC256"`
	Password string `arg required name:"password" help:"Password for AES256 encryption of private keys"`
	Path     string `flag optional name:"path" help:"Path to store keys. File names are 'yourname_bpm/yourname_bpm.pub' and 'yourname_km/yourname_km.pub' respectivly"`
}

func (v *versionCmd) Run(ctx *context) error {
	tools.ShowVersion(programName, gittag, gitcommit)
	return nil
}

func (kmp *kmPrintCmd) Run(ctx *context) error {
	data, err := ioutil.ReadFile(kmp.Path)
	if err != nil {
		return err
	}
	reader := bytes.NewReader(data)
	km, err := bg.ParseKM(reader)
	if err != nil {
		return err
	}
	km.Print()
	if km.KeyAndSignature.Signature.DataTotalSize() > 1 {
		if err := km.KeyAndSignature.Key.PrintKMPubKey(km.PubKeyHashAlg); err != nil {
			return err
		}
	}
	return nil
}

func (bpmp *bpmPrintCmd) Run(ctx *context) error {
	data, err := ioutil.ReadFile(bpmp.Path)
	if err != nil {
		return err
	}
	reader := bytes.NewReader(data)
	bpm, err := bg.ParseBPM(reader)
	if err != nil {
		return err
	}
	bpm.Print()
	if bpm.PMSE.Signature.DataTotalSize() > 1 {
		if err := bpm.PMSE.KeySignature.Key.PrintBPMPubKey(bpm.PMSE.Signature.HashAlg); err != nil {
			return err
		}
	}
	return nil
}

func (acmp *acmPrintCmd) Run(ctx *context) error {
	data, err := ioutil.ReadFile(acmp.Path)
	if err != nil {
		return err
	}
	acm, chipsets, processors, tpms, err, err2 := tools.ParseACM(data)
	if err != nil {
		return err
	}
	if err2 != nil {
		return err2
	}
	acm.PrettyPrint()
	chipsets.PrettyPrint()
	processors.PrettyPrint()
	tpms.PrettyPrint()
	return nil
}

func (biosp *biosPrintCmd) Run(ctx *context) error {
	data, err := ioutil.ReadFile(biosp.Path)
	if err != nil {
		return err
	}
	err = bg.PrintFIT(data)
	if err != nil {
		return err
	}
	err = bg.PrintBootGuardStructures(data)
	if err != nil {
		return err
	}
	return nil
}

func (acme *acmExportCmd) Run(ctx *context) error {
	data, err := ioutil.ReadFile(acme.BIOS)
	if err != nil {
		return err
	}
	acmfile, err := os.Create(acme.Out)
	if err != nil {
		return err
	}
	err = bg.WriteBootGuardStructures(data, nil, nil, acmfile)
	if err != nil {
		return err
	}
	return nil
}

func (kme *kmExportCmd) Run(ctx *context) error {
	data, err := ioutil.ReadFile(kme.BIOS)
	if err != nil {
		return err
	}
	kmfile, err := os.Create(kme.Out)
	if err != nil {
		return err
	}
	err = bg.WriteBootGuardStructures(data, nil, kmfile, nil)
	if err != nil {
		return err
	}
	return nil
}

func (bpme *bpmExportCmd) Run(ctx *context) error {
	data, err := ioutil.ReadFile(bpme.BIOS)
	if err != nil {
		return err
	}
	bpmfile, err := os.Create(bpme.Out)
	if err != nil {
		return err
	}
	err = bg.WriteBootGuardStructures(data, bpmfile, nil, nil)
	if err != nil {
		return err
	}
	return nil
}

func (g *generateKMCmd) Run(ctx *context) error {
	var options *bg.BootGuardOptions
	if g.Config != "" {
		bgo, err := bg.ParseConfig(g.Config)
		if err != nil {
			return err
		}
		options = bgo
	} else {
		var bgo bg.BootGuardOptions
		tmpKM := key.NewManifest()
		tmpKM.Revision = g.Revision
		tmpKM.KMSVN = g.SVN
		tmpKM.KMID = g.ID
		tmpKM.PubKeyHashAlg = g.PKHashAlg
		tmpKM.Hash = g.KMHashes
		// Create KM_Hash for BPM pub signing key
		if g.BpmPubkey != "" {
			kh, err := bg.GetBPMPubHash(g.BpmPubkey, g.BpmHashAlg)
			if err != nil {
				return err
			}
			tmpKM.Hash = kh
		}
		bgo.KeyManifest = *tmpKM
		options = &bgo
	}

	key, err := bg.ReadPubKey(g.Key)
	if err != nil {
		return err
	}

	if err := options.KeyManifest.KeyAndSignature.Key.SetPubKey(key); err != nil {
		return err
	}
	if g.PrintME {
		if options.KeyManifest.KeyAndSignature.Signature.DataTotalSize() > 1 {
			if err := options.KeyManifest.KeyAndSignature.Key.PrintKMPubKey(options.KeyManifest.PubKeyHashAlg); err != nil {
				return err
			}
		}
	}
	bKM, err := bg.WriteKM(&options.KeyManifest)
	if err != nil {
		return err
	}
	if g.Out != "" {
		out, err := os.Create(g.Out)
		if err != nil {
			return err
		}
		if err := bg.WriteConfig(out, options); err != nil {
			return err
		}
	}

	if g.Cut == true {
		//Cut signature from binary
		bKM = bKM[:int(options.KeyManifest.KeyManifestSignatureOffset)]
	}
	if err = ioutil.WriteFile(g.KM, bKM, 0600); err != nil {
		return fmt.Errorf("unable to write KM to file: %w", err)
	}
	return nil
}

func (g *generateBPMCmd) Run(ctx *context) error {
	var options *bg.BootGuardOptions
	if g.Config != "" {
		bgo, err := bg.ParseConfig(g.Config)
		if err != nil {
			return err
		}
		options = bgo
	} else {
		var bgo bg.BootGuardOptions
		bgo.BootPolicyManifest.BPMH.BPMRevision = g.Revision
		bgo.BootPolicyManifest.BPMH.BPMSVN = g.SVN
		bgo.BootPolicyManifest.BPMH.ACMSVNAuth = g.ACMSVN
		bgo.BootPolicyManifest.BPMH.NEMDataStack = g.NEMS

		se := bootpolicy.NewSE()
		se.PBETValue = g.PBET
		se.Flags = g.IBBSegFlags
		se.IBBMCHBAR = g.MCHBAR
		se.VTdBAR = g.VDTBAR
		se.DMAProtBase0 = g.DMABase0
		se.DMAProtLimit0 = g.DMASize0
		se.DMAProtBase1 = g.DMABase1
		se.DMAProtLimit1 = g.DMASize1
		se.IBBEntryPoint = g.EntryPoint

		se.DigestList.List = make([]manifest.HashStructure, len(g.IbbHash))
		se.DigestList.Size = uint16(len(g.IbbHash))
		for iterator := range se.DigestList.List {
			se.DigestList.List[iterator].HashAlg = g.IbbHash[iterator]
		}

		seg := *bootpolicy.NewIBBSegment()
		seg.Base = g.IbbSegbase
		seg.Size = g.IbbSegsize
		seg.Flags = g.IbbSegFlag
		se.IBBSegments = append(se.IBBSegments, seg)

		bgo.BootPolicyManifest.SE = append(bgo.BootPolicyManifest.SE, *se)

		txt := bootpolicy.NewTXT()
		txt.SInitMinSVNAuth = g.SintMin
		txt.ControlFlags = g.TXTFlags
		txt.PwrDownInterval = g.PowerDownInterval
		txt.ACPIBaseOffset = g.ACPIBaseOffset
		txt.PwrMBaseOffset = g.PowermBaseOffset
		txt.PTTCMOSOffset0 = g.CMOSOff0
		txt.PTTCMOSOffset1 = g.CMOSOff1

		bgo.BootPolicyManifest.TXTE = txt

		options = &bgo
	}

	bpm, err := bg.GenerateBPM(options, g.BIOS)
	if err != nil {
		return err
	}

	// This section is hacky, just to make the parsing work
	bpm.PMSE.Key.KeyAlg = 0x01
	bpm.PMSE.Signature.HashAlg = 0x01
	// End of hacky section
	if g.Out != "" {
		out, err := os.Create(g.Out)
		if err != nil {
			return err
		}
		if err := bg.WriteConfig(out, options); err != nil {
			return err
		}
	}
	bBPM, err := bg.WriteBPM(bpm)
	if err != nil {
		return err
	}
	if g.Cut {
		bBPM = bBPM[:bpm.KeySignatureOffset]
	}
	if err = ioutil.WriteFile(g.BPM, bBPM, 0600); err != nil {
		return fmt.Errorf("unable to write BPM to file: %w", err)
	}
	return nil
}

func (s *signKMCmd) Run(ctx *context) error {
	encKey, err := ioutil.ReadFile(s.Key)
	if err != nil {
		return err
	}
	privkey, err := bg.DecryptPrivKey(encKey, s.Password)
	if err != nil {
		return err
	}
	kmRaw, err := ioutil.ReadFile(s.KmIn)
	if err != nil {
		return err
	}
	var km key.Manifest
	r := bytes.NewReader(kmRaw)
	_, err = km.ReadFrom(r)
	if err != nil {
		return err
	}
	km.RehashRecursive()
	unsignedKM := kmRaw[:km.KeyAndSignatureOffset()]
	if err = km.SetSignature(0, privkey.(crypto.Signer), unsignedKM); err != nil {
		return err
	}
	bKMSigned, err := bg.WriteKM(&km)
	if err != nil {
		return err
	}
	if err := ioutil.WriteFile(s.KmOut, bKMSigned, 0600); err != nil {
		return err
	}
	return nil
}

func (s *signBPMCmd) Run(ctx *context) error {
	encKey, err := ioutil.ReadFile(s.Key)
	if err != nil {
		return err
	}
	key, err := bg.DecryptPrivKey(encKey, s.Password)
	if err != nil {
		return err
	}
	bpmRaw, err := ioutil.ReadFile(s.BpmIn)
	if err != nil {
		return err
	}

	var bpm bootpolicy.Manifest
	r := bytes.NewReader(bpmRaw)
	if _, err = bpm.ReadFrom(r); err != nil && !errors.Is(err, io.EOF) {
		return err
	}
	kAs := bootpolicy.NewSignature()
	switch key := key.(type) {
	case *rsa.PrivateKey:
		kAs.Key.SetPubKey(key.Public())
	case *ecdsa.PrivateKey:
		kAs.Key.SetPubKey(key.Public())
	default:
		return fmt.Errorf("Invalid key type")
	}
	bpm.PMSE = *kAs
	bpmRaw, err = bg.WriteBPM(&bpm)
	if err != nil {
		return err
	}
	bpm.RehashRecursive()
	unsignedBPM := bpmRaw[:bpm.KeySignatureOffset]
	//err = bpm.PMSE.SetSignature(0, key.(crypto.Signer), unsignedBPM)
	err = bpm.PMSE.Signature.SetSignature(0, key.(crypto.Signer), unsignedBPM)
	if err != nil {
		return fmt.Errorf("unable to make a signature: %w", err)
	}
	bBPMSigned, err := bg.WriteBPM(&bpm)
	if err != nil {
		return err
	}
	if err = ioutil.WriteFile(s.BpmOut, bBPMSigned, 0600); err != nil {
		return fmt.Errorf("unable to write BPM to file: %w", err)
	}
	return nil
}

func (t *templateCmd) Run(ctx *context) error {
	var bgo bg.BootGuardOptions
	km := *key.NewManifest()
	bpm := *bootpolicy.NewManifest()

	bpm.BPMRevision = t.Revision
	bpm.BPMSVN = t.SVN
	bpm.ACMSVNAuth = t.ACMSVN
	bpm.NEMDataStack = t.NEMS

	se := bootpolicy.NewSE()
	se.PBETValue = t.PBET
	se.Flags = t.IBBSegFlags
	se.IBBMCHBAR = t.MCHBAR
	se.VTdBAR = t.VDTBAR
	se.DMAProtBase0 = t.DMABase0
	se.DMAProtLimit0 = t.DMASize0
	se.DMAProtBase1 = t.DMABase1
	se.DMAProtLimit1 = t.DMASize1
	se.IBBEntryPoint = t.EntryPoint

	seg := *bootpolicy.NewIBBSegment()
	seg.Base = t.IbbSegbase
	seg.Size = t.IbbSegsize
	seg.Flags = t.IbbSegFlag
	se.IBBSegments = append(se.IBBSegments, seg)

	bpm.SE = append(bpm.SE, *se)

	txt := bootpolicy.NewTXT()
	txt.SInitMinSVNAuth = t.SintMin
	txt.ControlFlags = t.TXTFlags
	txt.PwrDownInterval = t.PowerDownInterval
	txt.ACPIBaseOffset = t.ACPIBaseOffset
	txt.PwrMBaseOffset = t.PowermBaseOffset
	txt.PTTCMOSOffset0 = t.CMOSOff0
	txt.PTTCMOSOffset1 = t.CMOSOff1

	bpm.TXTE = txt

	bgo.BootPolicyManifest = bpm
	bgo.KeyManifest = km

	out, err := os.Create(t.Path)
	if err != nil {
		return err
	}
	if err := bg.WriteConfig(out, &bgo); err != nil {
		return err
	}
	return nil
}

func (rc *readConfigCmd) Run(ctx *context) error {
	f, err := os.Create(rc.Config)
	if err != nil {
		return err
	}
	_, err = bg.ReadConfigFromBIOSImage(rc.BIOS, f)
	if err != nil {
		return err
	}
	return nil
}

func (s *stitchingKMCmd) Run(ctx *context) error {
	kmData, err := ioutil.ReadFile(s.KM)
	if err != nil {
		return err
	}
	sig, err := ioutil.ReadFile(s.Signature)
	if err != nil {
		return err
	}
	pub, err := bg.ReadPubKey(s.PubKey)
	if err != nil {
		return err
	}
	if len(kmData) < 1 || len(sig) < 1 {
		return fmt.Errorf("loaded files are empty")
	}
	reader := bytes.NewReader(kmData)
	km, err := bg.ParseKM(reader)
	if err != nil {
		return err
	}
	kmRaw, err := bg.StitchKM(km, pub, sig)
	if err != nil {
		return err
	}
	if err := ioutil.WriteFile(s.Out, kmRaw, 0644); err != nil {
		return err
	}
	return nil
}

func (s *stitchingBPMCmd) Run(ctx *context) error {
	bpmData, err := ioutil.ReadFile(s.BPM)
	if err != nil {
		return err
	}
	sig, err := ioutil.ReadFile(s.Signature)
	if err != nil {
		return err
	}
	pub, err := bg.ReadPubKey(s.PubKey)
	if err != nil {
		return err
	}
	if len(bpmData) < 1 || len(sig) < 1 {
		return fmt.Errorf("loaded files are empty")
	}
	reader := bytes.NewReader(bpmData)
	bpm, err := bg.ParseBPM(reader)
	if err != nil {
		return err
	}
	bpmRaw, err := bg.StitchBPM(bpm, pub, sig)
	if err != nil {
		return err
	}
	if err := ioutil.WriteFile(s.Out, bpmRaw, 0644); err != nil {
		return err
	}
	return nil
}

func (s *stitchingCmd) Run(ctx *context) error {
	var err error
	var bpm, km, acm, me []byte
	if s.BPM != "" {
		if bpm, err = ioutil.ReadFile(s.BPM); err != nil {
			return err
		}
	}
	if s.KM != "" {
		if km, err = ioutil.ReadFile(s.KM); err != nil {
			return err
		}
	}
	if s.ACM != "" {
		if acm, err = ioutil.ReadFile(s.ACM); err != nil {
			return err
		}
	}
	if s.ME != "" {
		if me, err = ioutil.ReadFile(s.ME); err != nil {
			return err
		}
	}
	if len(acm) == 0 && len(km) == 0 && len(bpm) == 0 && len(me) == 0 {
		return fmt.Errorf("at least one optional parameter required")
	}
	if err := bg.StitchFITEntries(s.BIOS, acm, bpm, km); err != nil {
		return err
	}
	if len(me) != 0 {
		image, err := ioutil.ReadFile(s.BIOS)
		if err != nil {
			return err
		}
		meRegionOffset, meRegionSize, err := tools.GetRegion(image, uefi.RegionTypeME)
		if len(me) > int(meRegionSize) {
			return fmt.Errorf("ME size exceeds region size! (%d > %d)", len(me), meRegionSize)
		}
		file, err := os.OpenFile(s.BIOS, os.O_RDWR, 0600)
		if err != nil {
			return err
		}
		defer file.Close()
		size, err := file.WriteAt(me, int64(meRegionOffset))
		if err != nil {
			return err
		}
		if size != len(me) {
			return fmt.Errorf("couldn't write new ME")
		}
	}
	return nil
}

func (k *keygenCmd) Run(ctx *context) error {
	kmPubFile, err := os.Create(k.Path + "km_pub.pem")
	if err != nil {
		return err
	}
	kmPrivFile, err := os.Create(k.Path + "km_priv.pem")
	if err != nil {
		return err
	}
	bpmPubFile, err := os.Create(k.Path + "bpm_pub.pem")
	if err != nil {
		return err
	}
	bpmPrivFile, err := os.Create(k.Path + "bpm_priv.pem")
	if err != nil {
		return err
	}

	switch k.Algo {
	case "RSA2048":
		err := bg.GenRSAKey(2048, k.Password, kmPubFile, kmPrivFile, bpmPubFile, bpmPrivFile)
		if err != nil {
			return err
		}
	case "RSA3072":
		err := bg.GenRSAKey(3072, k.Password, kmPubFile, kmPrivFile, bpmPubFile, bpmPrivFile)
		if err != nil {
			return err
		}
	case "ECC224":
		err := bg.GenECCKey(224, k.Password, kmPubFile, kmPrivFile, bpmPubFile, bpmPrivFile)
		if err != nil {
			return err
		}
	case "ECC256":
		err := bg.GenECCKey(256, k.Password, kmPubFile, kmPrivFile, bpmPubFile, bpmPrivFile)
		if err != nil {
			return err
		}
	default:
		return fmt.Errorf("Chosen algorithm invlid. Options are: RSA2048, RSA3072, ECC224, ECC256")
	}

	return nil
}

var cli struct {
	Debug                    bool `help:"Enable debug mode."`
	ManifestStrictOrderCheck bool `help:"Enable checking of manifest elements order"`

	KMShow   kmPrintCmd     `cmd help:"Prints Key Manifest binary in human-readable format"`
	KMGen    generateKMCmd  `cmd help:"Generate KM file based von json configuration"`
	KMSign   signKMCmd      `cmd help:"Sign key manifest with given key"`
	KMStitch stitchingKMCmd `cmd help:"Stitches KM Signatue into unsigned KM"`
	KMExport kmExportCmd    `cmd help:"Exports KM structures from BIOS image into file"`

	BPMShow   bpmPrintCmd     `cmd help:"Prints Boot Policy Manifest binary in human-readable format"`
	BPMGen    generateBPMCmd  `cmd help:"Generate BPM file based von json configuration"`
	BPMSign   signBPMCmd      `cmd help:"Sign Boot Policy Manifest with given key"`
	BPMStitch stitchingBPMCmd `cmd help:"Stitches BPM Signatue into unsigned BPM"`
	BPMExport bpmExportCmd    `cmd help:"Exports BPM structures from BIOS image into file"`

	ACMExport acmExportCmd `cmd help:"Exports ACM structures from BIOS image into file"`
	ACMShow   acmPrintCmd  `cmd help:"Prints ACM binary in human-readable format"`

	ShowAll    biosPrintCmd  `cmd help:"Prints BPM, KM, FIT and ACM from BIOS binary in human-readable format"`
	Stitch     stitchingCmd  `cmd help:"Stitches BPM, KM and ACM into given BIOS image file"`
	KeyGen     keygenCmd     `cmd help:"Generates key for KM and BPM signing"`
	Template   templateCmd   `cmd help:"Writes template JSON configuration into file"`
	ReadConfig readConfigCmd `cmd help:"Reads config from existing BIOS file and translates it to a JSON configuration"`
	Version    versionCmd    `cmd help:"Prints the version of the program"`
}
