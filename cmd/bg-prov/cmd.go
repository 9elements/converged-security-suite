package main

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"os"

	"github.com/linuxboot/fiano/pkg/intel/metadata/bg"
	"github.com/linuxboot/fiano/pkg/intel/metadata/bg/bgbootpolicy"
	"github.com/linuxboot/fiano/pkg/intel/metadata/bg/bgkey"
	"github.com/linuxboot/fiano/pkg/intel/metadata/cbnt"
	"github.com/linuxboot/fiano/pkg/intel/metadata/cbnt/cbntbootpolicy"
	"github.com/linuxboot/fiano/pkg/intel/metadata/cbnt/cbntkey"
	"github.com/linuxboot/fiano/pkg/intel/metadata/common/bgheader"
	"github.com/linuxboot/fiano/pkg/intel/metadata/fit"

	"github.com/linuxboot/fiano/pkg/uefi"

	"github.com/9elements/converged-security-suite/v2/pkg/provisioning/bootguard"
	"github.com/9elements/converged-security-suite/v2/pkg/tools"
)

type context struct {
	Debug bool
}

type versionCmd struct {
}

type templateCmdv1 struct {
	Path string `arg required name:"path" help:"Path to the newly generated JSON configuration file." type:"path"`
	//CBnT Manifest Header args
	Revision uint8               `flag optional name:"revision" help:"Platform Manufacturer’s BPM revision number."`
	SVN      bg.SVN              `flag optional name:"svn" help:"Boot Policy Manifest Security Version Number"`
	ACMSVN   bg.SVN              `flag optional name:"acmsvn" help:"Authorized ACM Security Version Number"`
	NEMS     bgbootpolicy.Size4K `flag optional name:"nems" help:"Size of data region need by IBB expressed in 4K pages. E.g., value of 1 = 4096 bytes; 2 = 8092 bytes, etc. Must not be zero"`
	// IBB args
	PBET        bgbootpolicy.PBETValue `flag optional name:"pbet" help:"Protect BIOS Environment Timer (PBET) value."`
	IBBSegFlags bgbootpolicy.SEFlags   `flag optional name:"ibbflags" help:"IBB Control flags"`
	MCHBAR      uint64                 `flag optional name:"mchbar" help:"MCHBAR address"`
	VDTBAR      uint64                 `flag optional name:"vdtbar" help:"VTDPVC0BAR address"`
	PMRLBase    uint32                 `flag optional name:"dmabase0" help:"Low DMA protected range base"`
	PMRLLimit   uint32                 `flag optional name:"dmasize0" help:"Low DMA protected range limit"`
	EntryPoint  uint32                 `flag optional name:"entrypoint" help:"IBB (Startup BIOS) entry point"`
	IbbHash     string                 `flag optional name:"ibbhash" help:"IBB Hash Algorithm. E.g.: SHA256, SHA384, SM3"`
}

type templateCmdv2 struct {
	Path string `arg required name:"path" help:"Path to the newly generated JSON configuration file." type:"path"`
	//CBnT Manifest Header args
	Revision uint8                 `flag optional name:"revision" help:"Platform Manufacturer’s BPM revision number."`
	SVN      cbnt.SVN              `flag optional name:"svn" help:"Boot Policy Manifest Security Version Number"`
	ACMSVN   cbnt.SVN              `flag optional name:"acmsvn" help:"Authorized ACM Security Version Number"`
	NEMS     cbntbootpolicy.Size4K `flag optional name:"nems" help:"Size of data region need by IBB expressed in 4K pages. E.g., value of 1 = 4096 bytes; 2 = 8092 bytes, etc. Must not be zero"`
	// IBB args
	PBET        cbntbootpolicy.PBETValue `flag optional name:"pbet" help:"Protect BIOS Environment Timer (PBET) value."`
	IBBSegFlags cbntbootpolicy.SEFlags   `flag optional name:"ibbflags" help:"IBB Control flags"`
	MCHBAR      uint64                   `flag optional name:"mchbar" help:"MCHBAR address"`
	VDTBAR      uint64                   `flag optional name:"vdtbar" help:"VTDPVC0BAR address"`
	DMABase0    uint32                   `flag optional name:"dmabase0" help:"Low DMA protected range base"`
	DMASize0    uint32                   `flag optional name:"dmasize0" help:"Low DMA protected range limit"`
	DMABase1    uint64                   `flag optional name:"dmabase1" help:"High DMA protected range base."`
	DMASize1    uint64                   `flag optional name:"dmasize1" help:"High DMA protected range limit."`
	EntryPoint  uint32                   `flag optional name:"entrypoint" help:"IBB (Startup BIOS) entry point"`
	IbbHash     []string                 `flag optional name:"ibbhash" help:"IBB Hash Algorithms. E.g.: SHA256, SHA384, SM3"`
	// TXT args
	SintMin           uint8                           `flag optional name:"sintmin" help:"OEM authorized SinitMinSvn value"`
	TXTFlags          cbntbootpolicy.TXTControlFlags  `flag optional name:"txtflags" help:"TXT Element control flags"`
	PowerDownInterval cbntbootpolicy.Duration16In5Sec `flag optional name:"powerdowninterval" help:"Duration of Power Down in 5 sec increments"`
	ACPIBaseOffset    uint16                          `flag optional name:"acpibaseoffset" help:"ACPI IO offset."`
	PowermBaseOffset  uint32                          `flag optional name:"powermbaseoffset" help:"ACPI MMIO offset."`
	CMOSOff0          uint8                           `flag optional name:"cmosoff0" help:"CMOS byte in bank 0 to store platform wakeup time"`
	CMOSOff1          uint8                           `flag optional name:"cmosoff1" help:"Second CMOS byte in bank 0 to store platform wakeup time"`
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

type generateACMCmdv3 struct {
	ACMOut           string `arg required name:"acm" help:"Path to the newly generated ACM headers binary file." type:"path"`
	ConfigIn         string `flag optional name:"config" help:"Path to the JSON config file." type:"path"`
	ConfigOut        string `flag optional name:"out" help:"Path to write applied config to" type:"path"`
	BodyPath         string `flag optional name:"bodypath" help:"Path to the ACM body" type:"path"`
	RSAPrivateKeyPEM string `flag optional name:"rsaprivkeypem" help:"RSA key used to sign the ACM" type:"path"`

	ModuleType      fit.ACModuleType    `flag optional name:"moduletype"`
	ModuleSubType   fit.ACModuleSubType `flag optional name:"modulesubtype"`
	ChipsetID       fit.ACChipsetID     `flag optional name:"chipsetid"`
	Flags           fit.ACFlags         `flag optional name:"flags"`
	ModuleVendor    fit.ACModuleVendor  `flag optional name:"modulevendor"`
	Date            fit.BCDDate         `flag optional name:"date"`
	Size            uint64              `flag optional name:"size"`
	TXTSVN          fit.TXTSVN          `flag optional name:"txtsvn"`
	SESVN           fit.SESVN           `flag optional name:"sesvn"`
	CodeControl     fit.CodeControl     `flag optional name:"codecontrol"`
	ErrorEntryPoint fit.ErrorEntryPoint `flag optional name:"errorentrypoint"`
	GDTLimit        fit.GDTLimit        `flag optional name:"gdtlimit"`
	GDTBasePtr      fit.GDTBasePtr      `flag optional name:"gdtbaseptr"`
	SegSel          fit.SegSel          `flag optional name:"segsel"`
	EntryPoint      fit.EntryPoint      `flag optional name:"entrypoint"`
}

type generateACMCmdv0 struct {
	ACMOut           string `arg required name:"acm" help:"Path to the newly generated ACM headers binary file." type:"path"`
	ConfigIn         string `flag optional name:"config" help:"Path to the JSON config file." type:"path"`
	ConfigOut        string `flag optional name:"out" help:"Path to write applied config to" type:"path"`
	BodyPath         string `flag optional name:"bodypath" help:"Path to the ACM body" type:"path"`
	RSAPrivateKeyPEM string `flag optional name:"rsaprivkeypem" help:"RSA key used to sign the ACM" type:"path"`

	ModuleType      fit.ACModuleType    `flag optional name:"moduletype"`
	ModuleSubType   fit.ACModuleSubType `flag optional name:"modulesubtype"`
	ChipsetID       fit.ACChipsetID     `flag optional name:"chipsetid"`
	Flags           fit.ACFlags         `flag optional name:"flags"`
	ModuleVendor    fit.ACModuleVendor  `flag optional name:"modulevendor"`
	Date            fit.BCDDate         `flag optional name:"date"`
	Size            uint64              `flag optional name:"size"`
	TXTSVN          fit.TXTSVN          `flag optional name:"txtsvn"`
	SESVN           fit.SESVN           `flag optional name:"sesvn"`
	CodeControl     fit.CodeControl     `flag optional name:"codecontrol"`
	ErrorEntryPoint fit.ErrorEntryPoint `flag optional name:"errorentrypoint"`
	GDTLimit        fit.GDTLimit        `flag optional name:"gdtlimit"`
	GDTBasePtr      fit.GDTBasePtr      `flag optional name:"gdtbaseptr"`
	SegSel          fit.SegSel          `flag optional name:"segsel"`
	EntryPoint      fit.EntryPoint      `flag optional name:"entrypoint"`
}

type generateKMCmdv1 struct {
	KM        string `arg required name:"km" help:"Path to the newly generated Key Manifest binary file." type:"path"`
	Key       string `arg required name:"key" help:"Public signing key"`
	Config    string `flag optional name:"config" help:"Path to the JSON config file." type:"path"`
	SVN       bg.SVN `flag optional name:"svn" help:"Boot Policy Manifest Security Version Number"`
	ID        uint8  `flag optional name:"id" help:"The key Manifest Identifier"`
	PKHashAlg string `flag optional name:"pkhashalg" help:"Hash algorithm of OEM public key digest. E.g.: SHA256, SHA384, SM3"`
	//KMHash     bg.HashStructure `flag optional name:"kmhash" help:"Key hash for BPM, ACM, uCode etc"`
	BpmPubkey  string `flag optional name:"bpmpubkey" help:"Path to bpm public signing key"`
	BpmHashAlg string `flag optional name:"bpmhashalgo" help:"Hash algorithm for bpm public signing cbntkey.. E.g.: SHA256, SHA384, SM3"`
	Out        string `flag optional name:"out" help:"Path to write applied config to"`
	Cut        bool   `flag optional name:"cut" help:"Cuts the signature before writing to binary."`
	PrintME    bool   `flag optional name:"printme" help:"Prints the hash of KM public signing key"`
}

type generateKMCmdv2 struct {
	KM         string         `arg required name:"km" help:"Path to the newly generated Key Manifest binary file." type:"path"`
	Key        string         `arg required name:"key" help:"Public signing key"`
	Config     string         `flag optional name:"config" help:"Path to the JSON config file." type:"path"`
	Revision   uint8          `flag optional name:"revision" help:"Platform Manufacturer’s BPM revision number."`
	SVN        cbnt.SVN       `flag optional name:"svn" help:"Boot Policy Manifest Security Version Number"`
	ID         uint8          `flag optional name:"id" help:"The key Manifest Identifier"`
	PKHashAlg  string         `flag optional name:"pkhashalg" help:"Hash algorithm of OEM public key digest. E.g.: SHA256, SHA384, SM3"`
	KMHashes   []cbntkey.Hash `flag optional name:"kmhashes" help:"Key hashes for BPM, ACM, uCode etc"`
	BpmPubkey  string         `flag optional name:"bpmpubkey" help:"Path to bpm public signing key"`
	BpmHashAlg string         `flag optional name:"bpmhashalgo" help:"Hash algorithm for bpm public signing cbntkey.. E.g.: SHA256, SHA384, SM3"`
	Out        string         `flag optional name:"out" help:"Path to write applied config to"`
	Cut        bool           `flag optional name:"cut" help:"Cuts the signature before writing to binary."`
	PrintME    bool           `flag optional name:"printme" help:"Prints the hash of KM public signing key"`
}

type generateBPMCmdv1 struct {
	BPM    string `arg required name:"bpm" help:"Path to the newly generated Boot Policy Manifest binary file." type:"path"`
	BIOS   string `arg required name:"bios" help:"Path to the full BIOS binary file." type:"path"`
	Config string `flag optional name:"config" help:"Path to the JSON config file." type:"path"`
	//CBnT Manifest Header args
	Revision uint8               `flag optional name:"revision" help:"Platform Manufacturer’s BPM revision number."`
	SVN      bg.SVN              `flag optional name:"svn" help:"Boot Policy Manifest Security Version Number"`
	ACMSVN   bg.SVN              `flag optional name:"acmsvn" help:"Authorized ACM Security Version Number"`
	NEMS     bgbootpolicy.Size4K `flag optional name:"nems" help:"Size of data region need by IBB expressed in 4K pages. E.g., value of 1 = 4096 bytes; 2 = 8092 bytes, etc. Must not be zero"`
	// IBB args
	PBET        bgbootpolicy.PBETValue `flag optional name:"pbet" help:"Protect BIOS Environment Timer (PBET) value."`
	IBBSegFlags bgbootpolicy.SEFlags   `flag optional name:"ibbflags" help:"IBB Control flags"`
	MCHBAR      uint64                 `flag optional name:"mchbar" help:"MCHBAR address"`
	VDTBAR      uint64                 `flag optional name:"vdtbar" help:"VTDPVC0BAR address"`
	PMRLBase    uint32                 `flag optional name:"dmabase0" help:"Low DMA protected range base"`
	PMRLLimit   uint32                 `flag optional name:"dmasize0" help:"Low DMA protected range limit"`
	EntryPoint  uint32                 `flag optional name:"entrypoint" help:"IBB (Startup BIOS) entry point"`
	IbbHash     []string               `flag optional name:"ibbhash" help:"IBB Hash Algorithm. Valid options: SHA256, SHA384, SM3"`
	IbbSegFlag  uint16                 `flag optional name:"ibbsegflag" help:"Reducted"`

	Out string `flag optional name:"out" help:"Path to write applied config to"`
	Cut bool   `flag optional name:"cut" help:"Cuts the signature before writing to binary."`
}

type generateBPMCmdv2 struct {
	BPM    string `arg required name:"bpm" help:"Path to the newly generated Boot Policy Manifest binary file." type:"path"`
	BIOS   string `arg required name:"bios" help:"Path to the full BIOS binary file." type:"path"`
	Config string `flag optional name:"config" help:"Path to the JSON config file." type:"path"`
	//CBnT Manifest Header args
	Revision uint8                 `flag optional name:"revision" help:"Platform Manufacturer’s BPM revision number."`
	SVN      cbnt.SVN              `flag optional name:"svn" help:"Boot Policy Manifest Security Version Number"`
	ACMSVN   cbnt.SVN              `flag optional name:"acmsvn" help:"Authorized ACM Security Version Number"`
	NEMS     cbntbootpolicy.Size4K `flag optional name:"nems" help:"Size of data region need by IBB expressed in 4K pages. E.g., value of 1 = 4096 bytes; 2 = 8092 bytes, etc. Must not be zero"`
	// IBB args
	PBET        cbntbootpolicy.PBETValue `flag optional name:"pbet" help:"Protect BIOS Environment Timer (PBET) value."`
	IBBSegFlags cbntbootpolicy.SEFlags   `flag optional name:"ibbflags" help:"IBB Control flags"`
	MCHBAR      uint64                   `flag optional name:"mchbar" help:"MCHBAR address"`
	VDTBAR      uint64                   `flag optional name:"vdtbar" help:"VTDPVC0BAR address"`
	DMABase0    uint32                   `flag optional name:"dmabase0" help:"Low DMA protected range base"`
	DMASize0    uint32                   `flag optional name:"dmasize0" help:"Low DMA protected range limit"`
	DMABase1    uint64                   `flag optional name:"dmabase1" help:"High DMA protected range base."`
	DMASize1    uint64                   `flag optional name:"dmasize1" help:"High DMA protected range limit."`
	EntryPoint  uint32                   `flag optional name:"entrypoint" help:"IBB (Startup BIOS) entry point"`
	IbbHash     []string                 `flag optional name:"ibbhash" help:"IBB Hash Algorithm. Valid options: SHA256, SHA384, SM3"`
	IbbSegFlag  uint16                   `flag optional name:"ibbsegflag" help:"Reducted"`
	// TXT args
	SinitMin          uint8                           `flag optional name:"sinitmin" help:"OEM authorized SinitMinSvn value"`
	TXTFlags          cbntbootpolicy.TXTControlFlags  `flag optional name:"txtflags" help:"TXT Element control flags"`
	PowerDownInterval cbntbootpolicy.Duration16In5Sec `flag optional name:"powerdowninterval" help:"Duration of Power Down in 5 sec increments"`
	ACPIBaseOffset    uint16                          `flag optional name:"acpibaseoffset" help:"ACPI IO offset."`
	PowermBaseOffset  uint32                          `flag optional name:"powermbaseoffset" help:"ACPI MMIO offset."`
	CMOSOff0          uint8                           `flag optional name:"cmosoff0" help:"CMOS byte in bank 0 to store platform wakeup time"`
	CMOSOff1          uint8                           `flag optional name:"cmosoff1" help:"Second CMOS byte in bank 0 to store platform wakeup time"`

	Out string `flag optional name:"out" help:"Path to write applied config to"`
	Cut bool   `flag optional name:"cut" help:"Cuts the signature before writing to binary."`
}

type signKMCmd struct {
	KmIn     string `arg required name:"kmin" help:"Path to the generated Key Manifest binary file." type:"path"`
	KmOut    string `arg required name:"kmout" help:"Path to write the signed KM to"`
	Key      string `arg required name:"km-keyfile" help:"Path to the encrypted PKCS8 private key file." type:"path"`
	SignAlgo string `arg required name:"signalgo" help:"Signing algorithm for KM. E.g.: RSASSA, RSAPSS, SM2"`
	Password string `arg required name:"password" help:"Password to decrypted PKCS8 private key file"`
}

type signBPMCmd struct {
	BpmIn    string `arg required name:"bpmin" help:"Path to the newly generated Boot Policy Manifest binary file." type:"path"`
	BpmOut   string `arg required name."bpmout" help:"Path to write the signed BPM to"`
	Key      string `arg required name:"bpm-keyfile" help:"Path to the encrypted PKCS8 private key file." type:"path"`
	SignAlgo string `arg required name:"signalgo" help:"Signing algorithm for KM. E.g.: RSASSA, RSAPSS, SM2"`
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
	ACM  string `arg required name:"acm" help:"Path to the ACM binary file." type:"path"`
	KM   string `arg required name:"km" help:"Path to the Key Manifest binary file." type:"path"`
	BPM  string `arg required name:"bpm" help:"Path to the Boot Policy Manifest binary file." type:"path"`
	ME   string `flag optional name:"me" help:"Path to the Management Engine binary file." type:"path"`
}

type keygenCmd struct {
	Algo     string `arg require name:"algo" help:"Select crypto algorithm for key generation. Options: RSA2048. RSA3072, ECC224, ECC256"`
	Password string `arg required name:"password" help:"Password for AES256 encryption of private keys"`
	Path     string `flag optional name:"path" help:"Path to store keys. File names are 'yourname_bpm/yourname_bpm.pub' and 'yourname_km/yourname_km.pub' respectivly"`
}

type printFITCmd struct {
	BIOS string `arg required name:"bios" help:"Path to the full BIOS binary file." type:"path"`
}

type verifyKMSigCmd struct {
	KM string `arg required name:"km" help:"Path to the Key Manifest binary file." type:"path"`
}
type verifyBPMSigCmd struct {
	BPM string `arg required name:"bpm" help:"Path to the Boot Policy Manifest binary file." type:"path"`
}

func (v *versionCmd) Run(ctx *context) error {
	tools.ShowVersion(programName, gittag, gitcommit)
	return nil
}

func (kmp *kmPrintCmd) Run(ctx *context) error {
	file, err := os.Open(kmp.Path)
	if err != nil {
		return err
	}
	defer file.Close()
	bg, err := bootguard.NewKM(file)
	if err != nil {
		return err

	}
	bg.PrintKM()
	return nil
}

func (bpmp *bpmPrintCmd) Run(ctx *context) error {
	file, err := os.Open(bpmp.Path)
	if err != nil {
		return err
	}
	defer file.Close()
	bg, err := bootguard.NewBPM(file)
	if err != nil {
		return err
	}
	bg.PrintBPM()
	return nil
}

func (acmp *acmPrintCmd) Run(ctx *context) error {
	file, err := os.Open(acmp.Path)
	if err != nil {
		return err
	}
	defer file.Close()
	acm, err := tools.ParseACM(file)
	if err != nil {
		return err
	}
	acm.PrettyPrint()
	return nil
}

func (biosp *biosPrintCmd) Run(ctx *context) error {
	data, err := os.ReadFile(biosp.Path)
	if err != nil {
		return err
	}
	table, err := fit.GetTable(data)
	if err != nil {
		return err
	}
	fmt.Printf("%s", table.String())
	err = bootguard.PrintStructures(data)
	if err != nil {
		return err
	}
	return nil
}

func (acme *acmExportCmd) Run(ctx *context) error {
	data, err := os.ReadFile(acme.BIOS)
	if err != nil {
		return err
	}
	acmfile, err := os.Create(acme.Out)
	if err != nil {
		return err
	}
	err = bootguard.WriteCBnTStructures(data, nil, nil, acmfile)
	if err != nil {
		return err
	}
	return nil
}

func (kme *kmExportCmd) Run(ctx *context) error {
	data, err := os.ReadFile(kme.BIOS)
	if err != nil {
		return err
	}
	kmfile, err := os.Create(kme.Out)
	if err != nil {
		return err
	}
	err = bootguard.WriteCBnTStructures(data, nil, kmfile, nil)
	if err != nil {
		return err
	}
	return nil
}

func (bpme *bpmExportCmd) Run(ctx *context) error {
	data, err := os.ReadFile(bpme.BIOS)
	if err != nil {
		return err
	}
	bpmfile, err := os.Create(bpme.Out)
	if err != nil {
		return err
	}
	err = bootguard.WriteCBnTStructures(data, bpmfile, nil, nil)
	if err != nil {
		return err
	}
	return nil
}

func (g *generateKMCmdv1) Run(ctx *context) error {
	var b bootguard.BootGuard
	b.Version = bgheader.Version10
	if g.Config != "" {
		err := b.ReadJSON(g.Config)
		if err != nil {
			return err
		}
	} else {
		var err error
		b.VData.BGkm = bgkey.NewManifest()
		b.VData.BGkm.KMSVN = g.SVN
		b.VData.BGkm.KMID = g.ID
		if err != nil {
			return err
		}
		//b.VData.BGkm.BPKey = g.KMHash
		// Create KM_Hash for BPM pub signing key
		if g.BpmPubkey != "" {
			pubkey, err := bootguard.ReadPubKey(g.BpmPubkey)
			if err != nil {
				return err
			}
			err = b.GetBPMPubHash(pubkey, g.BpmHashAlg)
			if err != nil {
				return err
			}
		} else {
			return fmt.Errorf("add --bpmpubkey=</path/to/bpm-pub-cbntkey.pem> as argument")
		}
	}
	key, err := bootguard.ReadPubKey(g.Key)
	if err != nil {
		return err
	}
	if err := b.VData.BGkm.KeyAndSignature.Key.SetPubKey(key); err != nil {
		return err
	}
	if g.PrintME {
		if b.VData.BGkm.KeyAndSignature.Signature.DataTotalSize() > 1 {
			if err := b.VData.BGkm.KeyAndSignature.Key.PrintKMPubKey(b.VData.BGkm.BPKey.HashAlg); err != nil {
				return err
			}
		}
	}
	bKM, err := b.WriteKM()
	if err != nil {
		return err
	}
	if g.Out != "" {
		out, err := os.Create(g.Out)
		if err != nil {
			return err
		}
		if err := b.WriteJSON(out); err != nil {
			return err
		}
	}
	if g.Cut {
		//Cut signature from binary
		bKM = bKM[:int(b.VData.BGkm.KeyAndSignatureOffset())]
	}
	if err = os.WriteFile(g.KM, bKM, 0600); err != nil {
		return fmt.Errorf("unable to write KM to file: %w", err)
	}
	return nil
}

func (g *generateKMCmdv2) Run(ctx *context) error {
	var b bootguard.BootGuard
	b.Version = bgheader.Version20
	if g.Config != "" {
		err := b.ReadJSON(g.Config)
		if err != nil {
			return err
		}
	} else {
		var err error
		b.VData.CBNTkm = cbntkey.NewManifest()
		b.VData.CBNTkm.Revision = g.Revision
		b.VData.CBNTkm.KMSVN = g.SVN
		b.VData.CBNTkm.KMID = g.ID
		b.VData.CBNTkm.PubKeyHashAlg, err = cbnt.GetAlgFromString(g.PKHashAlg)
		if err != nil {
			return err
		}
		b.VData.CBNTkm.Hash = g.KMHashes
		// Create KM_Hash for BPM pub signing key
		if g.BpmPubkey != "" {
			pubkey, err := bootguard.ReadPubKey(g.BpmPubkey)
			if err != nil {
				return err
			}
			err = b.GetBPMPubHash(pubkey, g.BpmHashAlg)
			if err != nil {
				return err
			}
		} else {
			return fmt.Errorf("add --bpmpubkey=</path/to/bpm-pub-cbntkey.pem> as argument")
		}
	}
	key, err := bootguard.ReadPubKey(g.Key)
	if err != nil {
		return err
	}
	if err := b.VData.CBNTkm.KeyAndSignature.Key.SetPubKey(key); err != nil {
		return err
	}
	if g.PrintME {
		if b.VData.CBNTkm.KeyAndSignature.Signature.DataTotalSize() > 1 {
			if err := b.VData.CBNTkm.KeyAndSignature.Key.PrintKMPubKey(b.VData.CBNTkm.PubKeyHashAlg); err != nil {
				return err
			}
		}
	}
	bKM, err := b.WriteKM()
	if err != nil {
		return err
	}
	if g.Out != "" {
		out, err := os.Create(g.Out)
		if err != nil {
			return err
		}
		if err := b.WriteJSON(out); err != nil {
			return err
		}
	}
	if g.Cut {
		//Cut signature from binary
		bKM = bKM[:int(b.VData.CBNTkm.KeyManifestSignatureOffset)]
	}
	if err = os.WriteFile(g.KM, bKM, 0600); err != nil {
		return fmt.Errorf("unable to write KM to file: %w", err)
	}
	return nil
}

func (g *generateBPMCmdv2) Run(ctx *context) error {
	var b bootguard.BootGuard
	if g.Config != "" {
		err := b.ReadJSON(g.Config)
		if err != nil {
			return err
		}
	} else {
		b.VData.CBNTbpm = cbntbootpolicy.NewManifest()
		b.VData.CBNTkm = cbntkey.NewManifest()

		se := cbntbootpolicy.NewSE()
		se.PBETValue = g.PBET
		se.Flags = g.IBBSegFlags
		se.IBBMCHBAR = g.MCHBAR
		se.VTdBAR = g.VDTBAR
		se.DMAProtBase0 = g.DMABase0
		se.DMAProtLimit0 = g.DMASize0
		se.DMAProtBase1 = g.DMABase1
		se.DMAProtLimit1 = g.DMASize1
		se.IBBEntryPoint = g.EntryPoint

		se.DigestList.List = make([]cbnt.HashStructure, len(g.IbbHash))
		se.DigestList.Size = uint16(len(g.IbbHash))

		ibbhashalgs := make([]cbnt.Algorithm, 0)
		for _, item := range g.IbbHash {
			hash, err := cbnt.GetAlgFromString(item)
			if err != nil {
				return err
			}
			ibbhashalgs = append(ibbhashalgs, hash)
		}

		for iterator := range se.DigestList.List {
			se.DigestList.List[iterator].HashAlg = ibbhashalgs[iterator]
		}

		ibbs, err := bootguard.FindAdditionalIBBs(g.BIOS)
		if err != nil {
			return fmt.Errorf("FindAdditionalIBBs: %w", err)
		}
		for counter := range ibbs {
			ibbs[counter].Flags = g.IbbSegFlag
		}
		se.IBBSegments = append(se.IBBSegments, ibbs...)

		b.VData.CBNTbpm.SE = append(b.VData.CBNTbpm.SE, *se)

		txt := cbntbootpolicy.NewTXT()
		txt.SInitMinSVNAuth = g.SinitMin
		txt.ControlFlags = g.TXTFlags
		txt.PwrDownInterval = g.PowerDownInterval
		txt.ACPIBaseOffset = g.ACPIBaseOffset
		txt.PwrMBaseOffset = g.PowermBaseOffset
		txt.PTTCMOSOffset0 = g.CMOSOff0
		txt.PTTCMOSOffset1 = g.CMOSOff1

		b.VData.CBNTbpm.TXTE = txt

		b.VData.CBNTbpm.PCDE = cbntbootpolicy.NewPCD()
		b.VData.CBNTbpm.PME = cbntbootpolicy.NewPM()
		b.VData.CBNTbpm.PMSE = *cbntbootpolicy.NewSignature()
		b.VData.CBNTbpm.BPMH = *cbntbootpolicy.NewBPMH()

		b.VData.CBNTbpm.BPMH.BPMRevision = g.Revision
		b.VData.CBNTbpm.BPMH.BPMSVN = g.SVN
		b.VData.CBNTbpm.BPMH.ACMSVNAuth = g.ACMSVN
		b.VData.CBNTbpm.BPMH.NEMDataStack = g.NEMS
	}
	bpm, err := b.GenerateBPMFromImage(g.BIOS)
	if err != nil {
		return fmt.Errorf("GenerateBPM: %w", err)
	}
	if g.Out != "" {
		out, err := os.Create(g.Out)
		if err != nil {
			return err
		}
		if err := b.WriteJSON(out); err != nil {
			return err
		}
	}
	bBPM, err := b.WriteBPM()
	if err != nil {
		return err
	}
	if g.Cut {
		bBPM = bBPM[:bpm.VData.CBNTbpm.KeySignatureOffset]
	}
	if err = os.WriteFile(g.BPM, bBPM, 0600); err != nil {
		return fmt.Errorf("unable to write BPM to file: %w", err)
	}
	return nil
}

func (g *generateACMCmdv0) Run(ctx *context) error {
	var sACM fit.EntrySACM
	var sACMData *fit.EntrySACMData
	if g.ConfigIn != "" {
		data, err := os.ReadFile(g.ConfigIn)
		if err != nil {
			return err
		}
		if err := sACM.UnmarshalJSON(data); err != nil {
			return err
		}
		sACMData, err = sACM.ParseData()
		if err != nil {
			return err
		}
	} else {
		var acmHeaders fit.EntrySACMData0
		acmHeaders.HeaderVersion = fit.ACHeaderVersion0
		acmHeaders.HeaderLen.SetSize(uint64(binary.Size(acmHeaders)))
		acmHeaders.ModuleType = g.ModuleType
		acmHeaders.ModuleSubType = g.ModuleSubType
		acmHeaders.ChipsetID = g.ChipsetID
		acmHeaders.Flags = g.Flags
		acmHeaders.ModuleVendor = g.ModuleVendor
		acmHeaders.Date = g.Date
		acmHeaders.Size.SetSize(g.Size)
		acmHeaders.TXTSVN = g.TXTSVN
		acmHeaders.SESVN = g.SESVN
		acmHeaders.CodeControl = g.CodeControl
		acmHeaders.ErrorEntryPoint = g.ErrorEntryPoint
		acmHeaders.GDTLimit = g.GDTLimit
		acmHeaders.GDTBasePtr = g.GDTBasePtr
		acmHeaders.SegSel = g.SegSel
		acmHeaders.EntryPoint = g.EntryPoint
		acmHeaders.KeySize.SetSize(256)
		sACMData.EntrySACMDataInterface = &acmHeaders
	}
	if g.ConfigOut != "" {
		buf := new(bytes.Buffer)
		_, err := sACMData.Write(buf.Bytes())
		if err != nil {
			return err
		}
		json, err := sACM.MarshalJSON()
		if err != nil {
			return err
		}
		if err := os.WriteFile(g.ConfigOut, json, 0700); err != nil {
			return err
		}
	}
	if g.BodyPath != "" {
		bodyData, err := os.ReadFile(g.BodyPath)
		if err != nil {
			return fmt.Errorf("unable to read the ACM body file '%s': %w", g.BodyPath, err)
		}

		sACMData.UserArea = bodyData
	}

	if g.RSAPrivateKeyPEM != "" {
		return fmt.Errorf("signing is not implemented, yet")
	}

	var acmBytes bytes.Buffer
	if _, err := sACMData.WriteTo(&acmBytes); err != nil {
		return fmt.Errorf("unable to compile the ACM module: %w", err)
	}

	if err := os.WriteFile(g.ACMOut, acmBytes.Bytes(), 0600); err != nil {
		return fmt.Errorf("unable to write KM to file: %w", err)
	}
	return nil
}

func (g *generateACMCmdv3) Run(ctx *context) error {
	var sACM fit.EntrySACM
	var sACMData *fit.EntrySACMData
	if g.ConfigIn != "" {
		data, err := os.ReadFile(g.ConfigIn)
		if err != nil {
			return err
		}
		if err := sACM.UnmarshalJSON(data); err != nil {
			return err
		}
		sACMData, err = sACM.ParseData()
		if err != nil {
			return err
		}
	} else {
		var acmHeaders fit.EntrySACMData3
		acmHeaders.HeaderVersion = fit.ACHeaderVersion3
		acmHeaders.HeaderLen.SetSize(uint64(binary.Size(acmHeaders)))
		acmHeaders.ModuleType = g.ModuleType
		acmHeaders.ModuleSubType = g.ModuleSubType
		acmHeaders.ChipsetID = g.ChipsetID
		acmHeaders.Flags = g.Flags
		acmHeaders.ModuleVendor = g.ModuleVendor
		acmHeaders.Date = g.Date
		acmHeaders.Size.SetSize(g.Size)
		acmHeaders.TXTSVN = g.TXTSVN
		acmHeaders.SESVN = g.SESVN
		acmHeaders.CodeControl = g.CodeControl
		acmHeaders.ErrorEntryPoint = g.ErrorEntryPoint
		acmHeaders.GDTLimit = g.GDTLimit
		acmHeaders.GDTBasePtr = g.GDTBasePtr
		acmHeaders.SegSel = g.SegSel
		acmHeaders.EntryPoint = g.EntryPoint
		acmHeaders.KeySize.SetSize(384)
		sACMData.EntrySACMDataInterface = &acmHeaders
	}
	if g.ConfigOut != "" {
		buf := new(bytes.Buffer)
		_, err := sACMData.Write(buf.Bytes())
		if err != nil {
			return err
		}
		json, err := sACM.MarshalJSON()
		if err != nil {
			return err
		}
		if err := os.WriteFile(g.ConfigOut, json, 0700); err != nil {
			return err
		}
	}
	if g.BodyPath != "" {
		bodyData, err := os.ReadFile(g.BodyPath)
		if err != nil {
			return fmt.Errorf("unable to read the ACM body file '%s': %w", g.BodyPath, err)
		}

		sACMData.UserArea = bodyData
	}

	if g.RSAPrivateKeyPEM != "" {
		return fmt.Errorf("signing is not implemented, yet")
	}

	var acmBytes bytes.Buffer
	if _, err := sACMData.WriteTo(&acmBytes); err != nil {
		return fmt.Errorf("unable to compile the ACM module: %w", err)
	}

	if err := os.WriteFile(g.ACMOut, acmBytes.Bytes(), 0600); err != nil {
		return fmt.Errorf("unable to write KM to file: %w", err)
	}
	return nil
}

func (s *signKMCmd) Run(ctx *context) error {
	encKey, err := os.ReadFile(s.Key)
	if err != nil {
		return err
	}
	privkey, err := bootguard.DecryptPrivKey(encKey, s.Password)
	if err != nil {
		return err
	}
	file, err := os.Open(s.KmIn)
	if err != nil {
		return err
	}
	defer file.Close()
	bg, err := bootguard.NewKM(file)
	if err != nil {
		return err
	}
	bKMSigned, err := bg.SignKM(s.SignAlgo, privkey)
	if err != nil {
		return err
	}
	if err := os.WriteFile(s.KmOut, bKMSigned, 0600); err != nil {
		return err
	}
	return nil
}

func (s *signBPMCmd) Run(ctx *context) error {
	encKey, err := os.ReadFile(s.Key)
	if err != nil {
		return err
	}
	key, err := bootguard.DecryptPrivKey(encKey, s.Password)
	if err != nil {
		return err
	}
	file, err := os.Open(s.BpmIn)
	if err != nil {
		return err
	}
	defer file.Close()
	bg, err := bootguard.NewBPM(file)
	if err != nil {
		return err
	}
	bBPMSigned, err := bg.SignBPM(s.SignAlgo, key)
	if err != nil {
		return err
	}
	if err = os.WriteFile(s.BpmOut, bBPMSigned, 0600); err != nil {
		return fmt.Errorf("unable to write BPM to file: %w", err)
	}
	return nil
}

func (t *templateCmdv2) Run(ctx *context) error {
	var vdata bootguard.VersionedData
	vdata.CBNTbpm = cbntbootpolicy.NewManifest()
	vdata.CBNTkm = cbntkey.NewManifest()

	vdata.CBNTbpm.BPMH.BPMRevision = t.Revision
	vdata.CBNTbpm.BPMH.BPMSVN = t.SVN
	vdata.CBNTbpm.BPMH.ACMSVNAuth = t.ACMSVN
	vdata.CBNTbpm.BPMH.NEMDataStack = t.NEMS

	se := cbntbootpolicy.NewSE()
	se.PBETValue = t.PBET
	se.Flags = t.IBBSegFlags
	se.IBBMCHBAR = t.MCHBAR
	se.VTdBAR = t.VDTBAR
	se.DMAProtBase0 = t.DMABase0
	se.DMAProtLimit0 = t.DMASize0
	se.DMAProtBase1 = t.DMABase1
	se.DMAProtLimit1 = t.DMASize1
	se.IBBEntryPoint = t.EntryPoint
	se.DigestList.List = make([]cbnt.HashStructure, len(t.IbbHash))

	ibbhashalgs := make([]cbnt.Algorithm, 0)
	for _, item := range t.IbbHash {
		hash, err := cbnt.GetAlgFromString(item)
		if err != nil {
			return err
		}
		ibbhashalgs = append(ibbhashalgs, hash)
	}

	for iterator := range se.DigestList.List {
		se.DigestList.List[iterator].HashAlg = ibbhashalgs[iterator]
	}

	vdata.CBNTbpm.SE = append(vdata.CBNTbpm.SE, *se)

	txt := cbntbootpolicy.NewTXT()
	txt.SInitMinSVNAuth = t.SintMin
	txt.ControlFlags = t.TXTFlags
	txt.PwrDownInterval = t.PowerDownInterval
	txt.ACPIBaseOffset = t.ACPIBaseOffset
	txt.PwrMBaseOffset = t.PowermBaseOffset
	txt.PTTCMOSOffset0 = t.CMOSOff0
	txt.PTTCMOSOffset1 = t.CMOSOff1

	vdata.CBNTbpm.TXTE = txt

	bootguard, err := bootguard.NewVData(vdata)
	if err != nil {
		return err
	}
	bBPM, err := bootguard.WriteBPM()
	if err != nil {
		return err
	}
	if err = os.WriteFile(t.Path, bBPM, 0600); err != nil {
		return fmt.Errorf("unable to write BPM to file: %w", err)
	}
	return nil
}

func (t *templateCmdv1) Run(ctx *context) error {
	var vdata bootguard.VersionedData
	var err error

	vdata.BGbpm = bgbootpolicy.NewManifest()
	vdata.BGkm = bgkey.NewManifest()

	vdata.BGbpm.BPMH.BPMSVN = t.SVN
	vdata.BGbpm.BPMH.ACMSVNAuth = t.ACMSVN
	vdata.BGbpm.BPMH.NEMDataStack = t.NEMS

	se := bgbootpolicy.NewSE()
	se.PBETValue = t.PBET
	se.Flags = t.IBBSegFlags
	se.IBBMCHBAR = t.MCHBAR
	se.VTdBAR = t.VDTBAR
	se.PMRLBase = t.PMRLBase
	se.PMRLLimit = t.PMRLLimit
	se.IBBEntryPoint = t.EntryPoint
	se.Digest.HashAlg, err = bg.GetAlgFromString(t.IbbHash)
	if err != nil {
		return err
	}
	vdata.BGbpm.SE = append(vdata.BGbpm.SE, *se)

	bootguard, err := bootguard.NewVData(vdata)
	if err != nil {
		return err
	}
	bBPM, err := bootguard.WriteBPM()
	if err != nil {
		return err
	}
	if err = os.WriteFile(t.Path, bBPM, 0600); err != nil {
		return fmt.Errorf("unable to write BPM to file: %w", err)
	}
	return nil
}

func (rc *readConfigCmd) Run(ctx *context) error {
	f, err := os.Create(rc.Config)
	if err != nil {
		return err
	}
	_, err = bootguard.NewBPMAndKMFromBIOS(rc.BIOS, f)
	if err != nil {
		return err
	}
	return nil
}

func (s *stitchingKMCmd) Run(ctx *context) error {
	file, err := os.Open(s.KM)
	if err != nil {
		return err
	}
	defer file.Close()
	sig, err := os.ReadFile(s.Signature)
	if err != nil {
		return err
	}
	pub, err := bootguard.ReadPubKey(s.PubKey)
	if err != nil {
		return err
	}
	if len(sig) < 1 {
		return fmt.Errorf("loaded files are empty")
	}
	bg, err := bootguard.NewKM(file)
	if err != nil {
		return err
	}
	km, err := bg.StitchKM(pub, sig)
	if err != nil {
		return err
	}
	if err := os.WriteFile(s.Out, km, 0644); err != nil {
		return err
	}
	return nil
}

func (s *stitchingBPMCmd) Run(ctx *context) error {
	file, err := os.Open(s.BPM)
	if err != nil {
		return err
	}
	defer file.Close()
	sig, err := os.ReadFile(s.Signature)
	if err != nil {
		return err
	}
	pub, err := bootguard.ReadPubKey(s.PubKey)
	if err != nil {
		return err
	}
	if len(sig) < 1 {
		return fmt.Errorf("loaded files are empty")
	}
	bg, err := bootguard.NewBPM(file)
	if err != nil {
		return err
	}
	bpm, err := bg.StitchBPM(pub, sig)
	if err != nil {
		return err
	}
	if err := os.WriteFile(s.Out, bpm, 0644); err != nil {
		return err
	}
	return nil
}

func (s *stitchingCmd) Run(ctx *context) error {
	var err error
	var bpm, km, acm, me []byte
	if s.BPM != "" {
		if bpm, err = os.ReadFile(s.BPM); err != nil {
			return err
		}
	}
	if s.KM != "" {
		if km, err = os.ReadFile(s.KM); err != nil {
			return err
		}
	}
	if s.ACM != "" {
		if acm, err = os.ReadFile(s.ACM); err != nil {
			return err
		}
	}
	if s.ME != "" {
		if me, err = os.ReadFile(s.ME); err != nil {
			return err
		}
	}
	if len(acm) == 0 && len(km) == 0 && len(bpm) == 0 && len(me) == 0 {
		return fmt.Errorf("at least one optional parameter required")
	}
	if err := bootguard.StitchFITEntries(s.BIOS, acm, bpm, km); err != nil {
		return err
	}
	if len(me) != 0 {
		image, err := os.ReadFile(s.BIOS)
		if err != nil {
			return err
		}
		meRegionOffset, meRegionSize, err := tools.GetRegion(image, uefi.RegionTypeME)
		if err != nil {
			return err
		}
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
		err := bootguard.GenRSAKey(2048, k.Password, kmPubFile, kmPrivFile, bpmPubFile, bpmPrivFile)
		if err != nil {
			return err
		}
	case "RSA3072":
		err := bootguard.GenRSAKey(3072, k.Password, kmPubFile, kmPrivFile, bpmPubFile, bpmPrivFile)
		if err != nil {
			return err
		}
	case "ECC224":
		err := bootguard.GenECCKey(224, k.Password, kmPubFile, kmPrivFile, bpmPubFile, bpmPrivFile)
		if err != nil {
			return err
		}
	case "ECC256":
		err := bootguard.GenECCKey(256, k.Password, kmPubFile, kmPrivFile, bpmPubFile, bpmPrivFile)
		if err != nil {
			return err
		}
	default:
		return fmt.Errorf("chosen algorithm invalid. Options are: RSA2048, RSA3072, ECC224, ECC256")
	}

	return nil
}

func (p printFITCmd) Run(ctx *context) error {
	img, err := os.ReadFile(p.BIOS)
	if err != nil {
		return err
	}
	table, err := fit.GetTable(img)
	if err != nil {
		return err
	}
	fmt.Printf("%s", table.String())
	return nil
}

func (v *verifyKMSigCmd) Run(ctx *context) error {
	file, err := os.Open(v.KM)
	if err != nil {
		return err
	}
	defer file.Close()
	bg, err := bootguard.NewKM(file)
	if err != nil {
		return err
	}
	return bg.VerifyKM()
}

func (b *verifyBPMSigCmd) Run(ctx *context) error {
	file, err := os.Open(b.BPM)
	if err != nil {
		return err
	}
	defer file.Close()
	bg, err := bootguard.NewBPM(file)
	if err != nil {
		return err
	}
	return bg.VerifyBPM()
}

var cli struct {
	Debug                    bool `help:"Enable debug mode."`
	ManifestStrictOrderCheck bool `help:"Enable checking of manifest elements order"`

	KMShow   kmPrintCmd      `cmd help:"Prints Key Manifest binary in human-readable format"`
	KMGenV1  generateKMCmdv1 `cmd help:"Generate v1 KM file based von json configuration"`
	KMGenV2  generateKMCmdv2 `cmd help:"Generate v2 KM file based von json configuration"`
	KMSign   signKMCmd       `cmd help:"Sign key manifest with given key"`
	KMVerify verifyKMSigCmd  `cmd help:"Verify the signature of a given KM"`
	KMStitch stitchingKMCmd  `cmd help:"Stitches KM Signatue into unsigned KM"`
	KMExport kmExportCmd     `cmd help:"Exports KM structures from BIOS image into file"`

	BPMShow   bpmPrintCmd      `cmd help:"Prints Boot Policy Manifest binary in human-readable format"`
	BPMGenV1  generateBPMCmdv1 `cmd help:"Generate v1 BPM file based von json configuration"`
	BPMGenV2  generateBPMCmdv2 `cmd help:"Generate v2 BPM file based von json configuration"`
	BPMSign   signBPMCmd       `cmd help:"Sign Boot Policy Manifest with given key"`
	BPMVerify verifyBPMSigCmd  `cmd help:"Verify the signature of a given KM"`
	BPMStitch stitchingBPMCmd  `cmd help:"Stitches BPM Signatue into unsigned BPM"`
	BPMExport bpmExportCmd     `cmd help:"Exports BPM structures from BIOS image into file"`

	ACMGenV0  generateACMCmdv0 `cmd help:"Generate an ACM v0 module (usable only for unit-tests)"`
	ACMGenV3  generateACMCmdv3 `cmd help:"Generate an ACM v3 module (usable only for unit-tests)"`
	ACMExport acmExportCmd     `cmd help:"Exports ACM structures from BIOS image into file"`
	ACMShow   acmPrintCmd      `cmd help:"Prints ACM binary in human-readable format"`

	FITShow printFITCmd `cmd help:"Prints the FIT Table of given BIOS image file"`

	ShowAll    biosPrintCmd  `cmd help:"Prints BPM, KM, FIT and ACM from BIOS binary in human-readable format"`
	Stitch     stitchingCmd  `cmd help:"Stitches BPM, KM and ACM into given BIOS image file"`
	KeyGen     keygenCmd     `cmd help:"Generates key for KM and BPM signing"`
	TemplateV1 templateCmdv1 `cmd help:"Writes template v1 JSON configuration into file"`
	TemplateV2 templateCmdv2 `cmd help:"Writes template v2 JSON configuration into file"`
	ReadConfig readConfigCmd `cmd help:"Reads config from existing BIOS file and translates it to a JSON configuration"`
	Version    versionCmd    `cmd help:"Prints the version of the program"`
}
