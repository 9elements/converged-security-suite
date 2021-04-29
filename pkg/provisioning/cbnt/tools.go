package cbnt

import (
	"bytes"
	"crypto/sha1"
	"encoding/binary"
	"fmt"
	"io"
	"io/ioutil"
	"os"

	"github.com/9elements/converged-security-suite/v2/pkg/hwapi"
	"github.com/9elements/converged-security-suite/v2/pkg/intel/metadata/fit"
	"github.com/9elements/converged-security-suite/v2/pkg/intel/metadata/manifest"
	"github.com/9elements/converged-security-suite/v2/pkg/intel/metadata/manifest/bootpolicy"
	"github.com/9elements/converged-security-suite/v2/pkg/intel/metadata/manifest/common/pretty"
	"github.com/9elements/converged-security-suite/v2/pkg/intel/metadata/manifest/key"
	"github.com/9elements/converged-security-suite/v2/pkg/tools"

	"github.com/linuxboot/cbfs/pkg/cbfs"
)

// WriteCBnTStructures takes a firmware image and extracts boot policy manifest, key manifest and acm into seperate files.
func WriteCBnTStructures(image []byte, bpmFile, kmFile, acmFile *os.File) error {
	bpm, km, acm, err := ParseFITEntries(image)
	if err != nil {
		return err
	}
	if bpmFile != nil && len(bpm.DataBytes) > 0 {
		if _, err = bpmFile.Write(bpm.DataBytes); err != nil {
			return err
		}
	}
	if kmFile != nil && len(km.DataBytes) > 0 {
		if _, err = kmFile.Write(km.DataBytes); err != nil {
			return err
		}
	}
	if acmFile != nil && len(acm.DataBytes) > 0 {
		if _, err = acmFile.Write(acm.DataBytes); err != nil {
			return err
		}
	}
	return nil
}

// PrintCBnTStructures takes a firmware image and prints boot policy manifest, key manifest, ACM, chipset, processor and tpm information if available.
func PrintCBnTStructures(image []byte) error {
	var acm *tools.ACM
	var chipsets *tools.Chipsets
	var processors *tools.Processors
	var tpms *tools.TPMs
	var err, err2 error
	bpmEntry, kmEntry, acmEntry, err := ParseFITEntries(image)
	if err != nil {
		return err
	}

	bpm, err := bpmEntry.ParseData()
	if err != nil {
		return fmt.Errorf("unable to parse BPM: %w", err)
	}

	km, err := kmEntry.ParseData()
	if err != nil {
		return fmt.Errorf("unable to parse KM: %w", err)
	}

	acm, chipsets, processors, tpms, err, err2 = tools.ParseACM(acmEntry.DataBytes)
	if err != nil || err2 != nil {
		return err
	}

	if bpm != nil {
		fmt.Println(bpm.PrettyString(0, true))
	}
	if km != nil {
		if km.KeyAndSignature.Signature.DataTotalSize() < 1 {
			fmt.Println(km.PrettyString(0, true, pretty.OptionOmitKeySignature(true)))
		} else {
			fmt.Println(km.PrettyString(0, true, pretty.OptionOmitKeySignature(false)))
		}
	}
	if acm != nil {
		acm.PrettyPrint()
		chipsets.PrettyPrint()
		processors.PrettyPrint()
		tpms.PrettyPrint()
	}
	return nil
}

// PrintFIT takes a firmware image and prints the Firmware Interface Table
func PrintFIT(image []byte) error {
	fitTable, err := fit.GetTable(image)
	if err != nil {
		return fmt.Errorf("unable to get FIT: %w", err)
	}
	fitEntries := fitTable.GetEntries(image)
	fmt.Println("----Firmware Interface Table----")
	fmt.Println()
	for idx, entry := range fitEntries {
		if entry.GetType() == fit.EntryTypeSkip || entry.GetType() == fit.EntryTypeFITHeaderEntry {
			continue
		}
		fmt.Printf("Entry %d\n", idx)
		fmt.Println(entry.GoString())
		fmt.Println()
	}
	fmt.Println()
	return nil
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

func generatePCR0Content(status uint64, km *key.Manifest, bpm *bootpolicy.Manifest, acm *tools.ACM) (*Pcr0Data, []byte, error) {
	var err error
	var pcr0 Pcr0Data
	buf := new(bytes.Buffer)
	if err = binary.Write(buf, binary.BigEndian, status); err != nil {
		return nil, nil, err
	}
	fmt.Printf("\nStatus: 0x%x\n ", status)
	if err = binary.Write(buf, binary.LittleEndian, acm.Header.TxtSVN); err != nil {
		return nil, nil, err
	}
	fmt.Printf("ACM SVN: 0x%x\n ", acm.Header.TxtSVN)
	if err = binary.Write(buf, binary.LittleEndian, acm.Header.Signature); err != nil {
		return nil, nil, err
	}
	fmt.Printf("ACM Sig: 0x%x\n ", acm.Header.Signature)

	{
		kmSignature, err := km.KeyAndSignature.Signature.SignatureData()
		if err != nil {
			return nil, nil, fmt.Errorf("unable to extract BPM signature: %w", err)
		}
		fmt.Printf("KM Sig: %s\n", kmSignature.String())
		switch kmSignature := kmSignature.(type) {
		case manifest.SignatureRSAASA:
			if err = binary.Write(buf, binary.LittleEndian, kmSignature); err != nil {
				return nil, nil, err
			}
		case manifest.SignatureECDSA:
			if err = binary.Write(buf, binary.LittleEndian, kmSignature.R); err != nil {
				return nil, nil, err
			}
		case manifest.SignatureSM2:
			if err = binary.Write(buf, binary.LittleEndian, kmSignature.R); err != nil {
				return nil, nil, err
			}
		default:
			return nil, nil, fmt.Errorf("unknown KM sig type: %T", kmSignature)
		}
	}

	{
		bpmSignature, err := bpm.PMSE.KeySignature.Signature.SignatureData()
		if err != nil {
			return nil, nil, fmt.Errorf("unable to extract BPM signature: %w", err)
		}
		fmt.Printf("BPM Sig: %s\n", bpmSignature.String())
		switch bpmSignature := bpmSignature.(type) {
		case manifest.SignatureRSAASA:
			if err = binary.Write(buf, binary.LittleEndian, bpmSignature); err != nil {
				return nil, nil, err
			}
		case manifest.SignatureECDSA:
			if err = binary.Write(buf, binary.LittleEndian, bpmSignature.R); err != nil {
				return nil, nil, err
			}
		case manifest.SignatureSM2:
			if err = binary.Write(buf, binary.LittleEndian, bpmSignature.R); err != nil {
				return nil, nil, err
			}
		default:
			return nil, nil, fmt.Errorf("unknown BPM sig type: %T", bpmSignature)
		}
	}

	for _, se := range bpm.SE {
		for i := 0; i < len(se.DigestList.List); i++ {
			if se.DigestList.List[i].HashAlg == manifest.AlgSHA1 {
				if err = binary.Write(buf, binary.LittleEndian, se.DigestList.List[i].HashBuffer); err != nil {
					return nil, nil, err
				}
				fmt.Printf("IBB Hash: 0x%x\n ", se.DigestList.List[i].HashBuffer)
			}
		}
	}

	h := sha1.New()
	h.Write(buf.Bytes())
	finalHash := h.Sum(nil)
	fmt.Printf("PCR-0 pre hash: 0x%x\n", finalHash)
	return &pcr0, finalHash, nil
}

// PrecalcPCR0 takes a firmware image and ACM Policy status and returns the Pcr0Data structure and its hash.
func PrecalcPCR0(data []byte, acmPolicySts uint64) (*Pcr0Data, []byte, error) {
	fitTable, err := fit.GetTable(data)
	if err != nil {
		return nil, nil, fmt.Errorf("unable to get FIT: %w", err)
	}
	fitEntries := fitTable.GetEntries(data)
	var km *key.Manifest
	var bpm *bootpolicy.Manifest
	var acm *tools.ACM
	for _, entry := range fitEntries {
		var err, err2 error
		switch entry := entry.(type) {
		case *fit.EntryBootPolicyManifestRecord:
			bpm, err = entry.ParseData()
		case *fit.EntryKeyManifestRecord:
			km, err = entry.ParseData()
		case *fit.EntrySACM:
			acm, _, _, _, err, err2 = tools.ParseACM(entry.GetDataBytes())
		}
		if err != nil {
			return nil, nil, err
		}
		if err2 != nil {
			return nil, nil, err2
		}
	}
	if acmPolicySts == 0 {
		txtAPI := hwapi.GetAPI()
		regs, err := tools.FetchTXTRegs(txtAPI)
		if err != nil {
			return nil, nil, err
		}
		acmPolicySts, err = tools.ReadACMPolicyStatusRaw(regs)
		if err != nil {
			return nil, nil, err
		}
	}
	return generatePCR0Content(acmPolicySts, km, bpm, acm)
}

// CalculateNEMSize calculates No Eviction Memory and returns it as count of 4K pages.
func CalculateNEMSize(image []byte, bpm *bootpolicy.Manifest, km *key.Manifest, acm *tools.ACM) (bootpolicy.Size4K, error) {
	var totalSize uint32
	if bpm == nil || km == nil || acm == nil {
		return 0, fmt.Errorf("BPM, KM or ACM are nil")
	}
	fitTable, err := fit.GetTable(image)
	if err != nil {
		return 0, fmt.Errorf("unable to get FIT: %w", err)
	}
	fitEntries := fitTable.GetEntries(image)
	if len(fitEntries) == 0 || fitEntries[0].GetType() != fit.EntryTypeFITHeaderEntry {
		return 0, fmt.Errorf("unable to get FIT headers")
	}
	hdr := fitEntries[0]
	if err != nil {
		return 0, err
	}
	totalSize += uint32(km.KeyManifestSignatureOffset)
	totalSize += keySignatureElementMaxSize
	totalSize += hdr.GetHeaders().DataSize()
	totalSize += uint32(2048)
	totalSize += keySignatureElementMaxSize
	totalSize += uint32((&bootpolicy.BPMH{}).TotalSize())
	for _, se := range bpm.SE {
		totalSize += uint32(se.ElementSize)
		for _, ibb := range se.IBBSegments {
			totalSize += ibb.Size
		}
	}
	if bpm.PCDE != nil {
		totalSize += uint32(bpm.PCDE.ElementSize)
	}
	if bpm.PME != nil {
		totalSize += uint32(bpm.PME.ElementSize)
	}
	totalSize += uint32(12)
	totalSize += keySignatureElementMaxSize
	if bpm.TXTE != nil {
		totalSize += uint32(bpm.TXTE.ElementSize)
	}
	totalSize += acm.Header.Size
	totalSize += defaultStackAndDataSize
	if (totalSize + additionalNEMSize) > defaultLLCSize {
		return 0, fmt.Errorf("NEM size is bigger than LLC %d", totalSize+additionalNEMSize)
	}
	if (totalSize % 4096) != 0 {
		totalSize += 4096 - (totalSize % 4096)
	}
	return bootpolicy.NewSize4K(totalSize), nil
}

// StitchFITEntries takes a firmware filename, an acm, a boot policy manifest and a key manifest as byte slices
// and writes the information into the Firmware Interface Table of the firmware image.
func StitchFITEntries(biosFilename string, acm, bpm, km []byte) error {
	image, err := ioutil.ReadFile(biosFilename)
	if err != nil {
		return err
	}
	fitTable, err := fit.GetTable(image)
	if err != nil {
		return fmt.Errorf("unable to get FIT: %w", err)
	}
	fitEntries := fitTable.GetEntries(image)
	file, err := os.OpenFile(biosFilename, os.O_RDWR, 0600)
	if err != nil {
		return err
	}
	defer file.Close()
	for _, entry := range fitEntries {
		switch entry := entry.(type) {
		case *fit.EntryBootPolicyManifestRecord:
			if len(bpm) <= 0 {
				continue
			}
			if len(entry.DataBytes) == 0 {
				return fmt.Errorf("FIT entry size is zero for BPM")
			}
			if len(bpm) > len(entry.DataBytes) {
				return fmt.Errorf("new BPM bigger than older BPM")
			}
			addr, err := tools.CalcImageOffset(image, entry.Headers.Address.Pointer())
			if err != nil {
				return err
			}
			_, err = file.Seek(0, 0)
			if err != nil {
				return err
			}
			size, err := file.WriteAt(bpm, int64(addr))
			if err != nil {
				return err
			}
			if size != len(bpm) {
				return fmt.Errorf("couldn't write new BPM")
			}
		case *fit.EntryKeyManifestRecord:
			if len(km) <= 0 {
				continue
			}
			if len(entry.DataBytes) == 0 {
				return fmt.Errorf("FIT entry size is zero for KM")
			}
			if len(km) > len(entry.DataBytes) {
				return fmt.Errorf("new KM bigger than older KM")
			}
			addr, err := tools.CalcImageOffset(image, entry.Headers.Address.Pointer())
			if err != nil {
				return err
			}
			_, err = file.Seek(0, 0)
			if err != nil {
				return err
			}
			size, err := file.WriteAt(km, int64(addr))
			if err != nil {
				return err
			}
			if size != len(km) {
				return fmt.Errorf("couldn't write new KM")
			}
		case *fit.EntrySACM:
			if len(acm) <= 0 {
				continue
			}
			addr, err := tools.CalcImageOffset(image, entry.Headers.Address.Pointer())
			if err != nil {
				return err
			}
			_, err = file.Seek(int64(addr), io.SeekStart)
			if err != nil {
				return err
			}
			acmHeader := make([]byte, 32)
			_, err = file.Read(acmHeader)
			if err != nil {
				return err
			}
			acmLen, err := tools.LookupACMSize(acmHeader)
			if err != nil {
				return err
			}
			if acmLen == 0 {
				return fmt.Errorf("ACM size is wrong")
			}
			if len(acm) != int(acmLen) {
				return fmt.Errorf("new ACM size doesn't equal old ACM size")
			}
			_, err = file.Seek(0, 0)
			if err != nil {
				return err
			}
			size, err := file.WriteAt(acm, int64(addr))
			if err != nil {
				return err
			}
			if size != len(acm) {
				return fmt.Errorf("couldn't write new ACM")
			}
		}
	}
	return nil
}

const (
	fspt     = "fspt.bin"
	verstage = "fallback/verstage"
)

// FindAdditionalIBBs takes a coreboot image and finds componentName to create
// additional IBBSegment.
func FindAdditionalIBBs(imagepath string) ([]bootpolicy.IBBSegment, error) {
	var ibbs []bootpolicy.IBBSegment
	image, err := os.Open(imagepath)
	if err != nil {
		return nil, err
	}
	defer image.Close()

	img, err := cbfs.NewImage(image)
	if err != nil {
		return nil, err
	}
	flashBase := 0xffffffff - len(img.Data) + 1
	for _, seg := range img.Segs {
		cbfsbaseaddr := img.Area.Offset
		if seg.GetFile().Name == fspt || seg.GetFile().Name == verstage {
			ibb := bootpolicy.NewIBBSegment()
			ibb.Base = uint32(flashBase) + cbfsbaseaddr + seg.GetFile().RecordStart + seg.GetFile().SubHeaderOffset
			ibb.Size = seg.GetFile().Size
			ibb.Flags = 0
			ibbs = append(ibbs, *ibb)
		}
	}
	return ibbs, nil
}
