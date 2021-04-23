package main

import (
	"bytes"
	"crypto"
	"crypto/rsa"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"os"

	"github.com/9elements/converged-security-suite/v2/pkg/intel/metadata/fit"

	"github.com/9elements/converged-security-suite/v2/pkg/provisioning/bootguard"
	"github.com/9elements/converged-security-suite/v2/pkg/provisioning/bootguard/bootpolicy"
	"github.com/9elements/converged-security-suite/v2/pkg/provisioning/bootguard/common"
	"github.com/9elements/converged-security-suite/v2/pkg/provisioning/bootguard/key"
)

type context struct {
	Debug bool
}

type versionCmd struct {
}

type generateKMCmd struct {
	KM         string           `arg required name:"path" help:"Path to the newly generated km binary file"`
	Key        string           `arg required name:"key" help:"Public signing key"`
	Config     string           `flag optional name:"config" help:"Path to the JSON config file." type:"path"`
	KMVersion  uint8            `flag optional name:"kmversion" help:"Platform Manufacturer’s BPM version number."`
	SVN        common.SVN       `flag optional name:"svn" help:"Boot Policy Manifest Security Version Number"`
	ID         uint8            `flag optional name:"id" help:"The key Manifest Identifier"`
	BpmPubkey  string           `flag optional name:"bpmpubkey" help:"Path to bpm public signing key"`
	BpmHashAlg common.Algorithm `flag optional name:"bpmhashalgo" help:"Hash algorithm for bpm public signing key"`
	Out        string           `flag optional name:"out" help:"Path to write applied config to"`
	Cut        bool             `flag optional name:"cut" help:"Cuts the signature before writing to binary."`
	PrintME    bool             `flag optional name:"printme" help:"Prints the hash of KM public signing key"`
}

type signKMCmd struct {
	KmIn     string `arg required name:"kmin" help:"Path to the generated Key Manifest binary file." type:"path"`
	KmOut    string `arg required name:"kmout" help:"Path to write the signed KM to"`
	Key      string `arg required name:"km-keyfile" help:"Path to the encrypted PKCS8 private key file." type:"path"`
	Password string `arg required name:"password" help:"Password to decrypted PKCS8 private key file"`
}

type kmPrintCmd struct {
	Path string `arg required name:"path" help:"Path to the km binary file"`
}

type kmExportCmd struct {
	BIOS string `arg required name:"bios" help:"Path to the full BIOS binary file." type:"path"`
	Out  string `arg required name:"out" help:"Path to the newly generated KM binary file." type:"path"`
}

type bpmPrintCmd struct {
	Path string `arg required name:"path" help:"Path to the km binary file"`
}

type bpmExportCmd struct {
	BIOS string `arg required name:"bios" help:"Path to the full BIOS binary file." type:"path"`
	Out  string `arg required name:"out" help:"Path to the newly generated KM binary file." type:"path"`
}

type bpmGenCmd struct {
	BPM    string `arg required name:"bpm" help:"Path to the newly generated Boot Policy Manifest binary file." type:"path"`
	BIOS   string `arg required name:"bios" help:"Path to the full BIOS binary file." type:"path"`
	Config string `flag optional name:"config" help:"Path to the JSON config file." type:"path"`

	PMBPMVersion uint8                `flag optional name:"pmbpmversion" help:"Platform Manufacturer’s BPM revision number."`
	SVN          common.SVN           `flag optional name:"svn" help:"Boot Policy Manifest Security Version Number"`
	ACMSVN       common.SVN           `flag optional name:"acmsvn" help:"Authorized ACM Security Version Number"`
	NEMS         bootpolicy.Size4K    `flag optional name:"nems" help:"Size of data region need by IBB expressed in 4K pages. E.g., value of 1 = 4096 bytes; 2 = 8092 bytes, etc. Must not be zero"`
	PBET         bootpolicy.PBETValue `flag optional name:"pbet" help:"Protect BIOS Environment Timer (PBET) value."`
	IBBSegFlags  bootpolicy.SEFlags   `flag optional name:"ibbflags" help:"IBB Control flags"`
	MCHBAR       uint64               `flag optional name:"mchbar" help:"MCHBAR address"`
	VDTBAR       uint64               `flag optional name:"vdtbar" help:"VTDPVC0BAR address"`
	PMRLBase     uint32               `flag optional name:"dmabase0" help:"Low DMA protected range base"`
	PMRLLimit    uint32               `flag optional name:"dmasize0" help:"Low DMA protected range limit"`
	EntryPoint   uint32               `flag optional name:"entrypoint" help:"IBB (Startup BIOS) entry point"`

	IbbSegFlag uint16 `flag optional name:"ibbsegflag" help:"Reducted"`

	Out string `flag optional name:"out" help:"Path to write applied config to"`
}

type bpmSignCmd struct {
	BpmIn    string `arg required name:"bpmin" help:"Path to the newly generated Boot Policy Manifest binary file." type:"path"`
	BpmOut   string `arg required name."bpmout" help:"Path to write the signed BPM to"`
	Key      string `arg required name:"bpm-keyfile" help:"Path to the encrypted PKCS8 private key file." type:"path"`
	Password string `arg required name:"password" help:"Password to decrypt PKCS8 private key file"`
}

type readAllCmd struct {
	BIOS   string `arg required name:"bios" help:"Path to the full BIOS binary file." type:"path"`
	Config string `arg required name:"config" help:"Path to the JSON config file." type:"path"`
}

type printFITCmd struct {
	BIOS string `arg required name:"bios" help:"Path to the full BIOS binary file." type:"path"`
}

func (g generateKMCmd) Run(ctx *context) error {
	var options *bootguard.Options
	if g.Config != "" {
		bgo, err := bootguard.ParseConfig(g.Config)
		if err != nil {
			return err
		}
		options = bgo
	} else {
		bgo := bootguard.NewOptions()
		bgo.KeyManifest.KMVersion = g.KMVersion
		bgo.KeyManifest.KMSVN = g.SVN
		bgo.KeyManifest.KMID = g.ID
		key, err := bootguard.GetBPMPubHash(g.BpmPubkey)
		if err != nil {
			return err
		}
		bgo.KeyManifest.BPKey = *key

		options = &bgo
	}

	key, err := bootguard.ReadPubKey(g.Key)
	if err != nil {
		return err
	}

	if err := options.KeyManifest.KeyAndSignature.Key.SetPubKey(key); err != nil {
		return err
	}
	if g.PrintME {
		if options.KeyManifest.KeyAndSignature.Signature.DataTotalSize() > 1 {
			if err := options.KeyManifest.KeyAndSignature.Key.PrintKMPubKey(common.AlgSHA256); err != nil {
				return err
			}
		}
	}

	bKM, err := bootguard.WriteKM(options.KeyManifest)
	if err != nil {
		return err
	}
	if g.Out != "" {
		out, err := os.Create(g.Out)
		if err != nil {
			return err
		}
		if err := bootguard.WriteConfig(out, options); err != nil {
			return err
		}
	}

	if err = ioutil.WriteFile(g.KM, bKM, 0600); err != nil {
		return fmt.Errorf("unable to write KM to file: %w", err)
	}
	return nil
}

func (kmp *kmPrintCmd) Run(ctx *context) error {
	data, err := ioutil.ReadFile(kmp.Path)
	if err != nil {
		return err
	}
	reader := bytes.NewReader(data)
	km, err := bootguard.ParseKM(reader)
	if err != nil {
		return err
	}
	km.Print()
	if km.KeyAndSignature.Signature.DataTotalSize() > 1 {
		if err := km.KeyAndSignature.Key.PrintKMPubKey(common.AlgSHA256); err != nil {
			return err
		}
	}
	return nil
}

func (s *signKMCmd) Run(ctx *context) error {
	encKey, err := ioutil.ReadFile(s.Key)
	if err != nil {
		return err
	}
	privkey, err := bootguard.DecryptPrivKey(encKey, s.Password)
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

	unsignedKM := kmRaw[:46]
	if err = km.SetSignature(0, privkey.(crypto.Signer), unsignedKM); err != nil {
		return err
	}
	bKMSigned, err := bootguard.WriteKM(&km)
	if err != nil {
		return err
	}
	if err := ioutil.WriteFile(s.KmOut, bKMSigned, 0600); err != nil {
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
	err = bootguard.WriteBGStructures(data, nil, kmfile, nil)
	if err != nil {
		return err
	}
	return nil
}

func (bpmp *bpmPrintCmd) Run(ctx *context) error {
	data, err := ioutil.ReadFile(bpmp.Path)
	if err != nil {
		return err
	}
	reader := bytes.NewReader(data)
	bpm, err := bootguard.ParseBPM(reader)
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

func (bpme *bpmExportCmd) Run(ctx *context) error {
	data, err := ioutil.ReadFile(bpme.BIOS)
	if err != nil {
		return err
	}
	bpmfile, err := os.Create(bpme.Out)
	if err != nil {
		return err
	}
	err = bootguard.WriteBGStructures(data, bpmfile, nil, nil)
	if err != nil {
		return err
	}
	return nil
}

func (g *bpmGenCmd) Run(ctx *context) error {
	var options *bootguard.Options
	if g.Config != "" {
		bgo, err := bootguard.ParseConfig(g.Config)
		if err != nil {
			return err
		}
		options = bgo
	} else {
		bgo := bootguard.NewOptions()
		bgo.BootPolicyManifest.BPMH.PMBPMVersion = g.PMBPMVersion
		bgo.BootPolicyManifest.BPMH.BPMSVN = g.SVN
		bgo.BootPolicyManifest.BPMH.ACMSVNAuth = g.ACMSVN
		bgo.BootPolicyManifest.BPMH.NEMDataStack = g.NEMS

		se := bootpolicy.NewSE()
		se.PBETValue = g.PBET
		se.Flags = g.IBBSegFlags
		se.IBBMCHBAR = g.MCHBAR
		se.VTdBAR = g.VDTBAR
		se.PMRLBase = g.PMRLBase
		se.PMRLLimit = g.PMRLLimit

		se.IBBEntryPoint = g.EntryPoint

		ibbs, err := bootguard.FindAdditionalIBBs(g.BIOS)
		if err != nil {
			return err
		}
		for counter := range ibbs {
			ibbs[counter].Flags = g.IbbSegFlag
		}
		se.IBBSegments = append(se.IBBSegments, ibbs...)

		bgo.BootPolicyManifest.SE = append(bgo.BootPolicyManifest.SE, *se)

		options = &bgo
	}

	bpm, err := bootguard.GenerateBPM(options, g.BIOS)
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
		if err := bootguard.WriteConfig(out, options); err != nil {
			return err
		}
	}
	bBPM, err := bootguard.WriteBPM(bpm)
	if err != nil {
		return err
	}
	if err = ioutil.WriteFile(g.BPM, bBPM, 0600); err != nil {
		return fmt.Errorf("unable to write BPM to file: %w", err)
	}

	return nil
}

func (b *bpmSignCmd) Run(ctx *context) error {
	encKey, err := ioutil.ReadFile(b.Key)
	if err != nil {
		return err
	}
	key, err := bootguard.DecryptPrivKey(encKey, b.Password)
	if err != nil {
		return err
	}
	bpmRaw, err := ioutil.ReadFile(b.BpmIn)
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
	default:
		return fmt.Errorf("Invalid key type")
	}
	bpm.PMSE = *kAs
	bpmRaw, err = bootguard.WriteBPM(&bpm)
	if err != nil {
		return err
	}
	unsignedBPM := bpmRaw[:bpm.PMSEOffset()+10]
	//err = bpm.PMSE.SetSignature(0, key.(crypto.Signer), unsignedBPM)
	err = bpm.PMSE.Signature.SetSignature(0, key.(crypto.Signer), unsignedBPM)
	if err != nil {
		return fmt.Errorf("unable to make a signature: %w", err)
	}
	bBPMSigned, err := bootguard.WriteBPM(&bpm)
	if err != nil {
		return err
	}
	if err = ioutil.WriteFile(b.BpmOut, bBPMSigned, 0600); err != nil {
		return fmt.Errorf("unable to write BPM to file: %w", err)
	}

	return nil
}

func (c readAllCmd) Run(ctx *context) error {
	cfg, err := os.Create(c.Config)
	if err != nil {
		return err
	}
	_, err = bootguard.ReadConfigFromBIOSImage(c.BIOS, cfg)
	if err != nil {
		return err
	}

	return nil
}

func (p *printFITCmd) Run(ctx *context) error {
	img, err := ioutil.ReadFile(p.BIOS)
	if err != nil {
		return err
	}
	table, err := fit.GetTable(img)
	if err != nil {
		return err
	}
	fmt.Printf("%s\n", table.String())
	return nil
}

var cli struct {
	Version    versionCmd    `cmd help:"Show version information of Intel BootGuard provisioning tool"`
	KmGen      generateKMCmd `cmd help:"Generate a BootGuard Key Manifest"`
	KmShow     kmPrintCmd    `cmd help:"Prints Key Manifest binary in human-readable format"`
	KmSign     signKMCmd     `cmd help:"Signs a given Key Manifest with the supplied private key"`
	KmExport   kmExportCmd   `cmd help:"Exports KM structures from BIOS image into file"`
	BpmShow    bpmPrintCmd   `cmd help:"Prints Bootpolicy Manifest binary in human-readable format"`
	BpmExport  bpmExportCmd  `cmd help:"Exports BPM structures from BIOS image into file"`
	BpmGen     bpmGenCmd     `cmd help:"Generate a Bootguard Bootpolicy Manifest"`
	BpmSign    bpmSignCmd    `cmd help:"Signs a given Bootpolicy Manifest with the supplied private key"`
	ReadConfig readAllCmd    `cmd help:"Reads config from given image file and saves it in config file in json format"`
	PrintFIT   printFITCmd   `cmd help:"Takes a firmware image and prints it FIT table in tabular form"`
}
