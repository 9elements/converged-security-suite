package bg

import (
	"bytes"
	"crypto/sha1"
	"encoding/binary"
	"fmt"
	"io"
	"io/ioutil"
	"os"

	"github.com/9elements/converged-security-suite/v2/pkg/hwapi"
	"github.com/9elements/converged-security-suite/v2/pkg/intel/metadata/manifest"
	"github.com/9elements/converged-security-suite/v2/pkg/intel/metadata/manifest/bootpolicy"
	"github.com/9elements/converged-security-suite/v2/pkg/intel/metadata/manifest/key"
	"github.com/9elements/converged-security-suite/v2/pkg/tools"
)

// WriteBootGuardStructures takes a firmware image and extracts boot policy manifest, key manifest and acm into seperate files.
func WriteBootGuardStructures(image []byte, bpmFile, kmFile, acmFile *os.File) error {
	bpmBuf, kmBuf, acmBuf, err := ParseFITEntries(image)
	if err != nil {
		return err
	}
	if bpmFile != nil && len(bpmBuf) > 0 {
		if _, err = bpmFile.Write(bpmBuf); err != nil {
			return err
		}
	}
	if kmFile != nil && len(kmBuf) > 0 {
		if _, err = kmFile.Write(kmBuf); err != nil {
			return err
		}
	}
	if acmFile != nil && len(acmBuf) > 0 {
		if _, err = acmFile.Write(acmBuf); err != nil {
			return err
		}
	}
	return nil
}

// PrintBootGuardStructures takes a firmware image and prints boot policy manifest, key manifest, ACM, chipset, processor and tpm information if available.
func PrintBootGuardStructures(image []byte) error {
	var km *key.Manifest
	var bpm *bootpolicy.Manifest
	var acm *tools.ACM
	var chipsets *tools.Chipsets
	var processors *tools.Processors
	var tpms *tools.TPMs
	var err, err2 error
	bpmBuf, kmBuf, acmBuf, err := ParseFITEntries(image)
	if err != nil {
		return err
	}
	reader := bytes.NewReader(bpmBuf)
	bpm, err = ParseBPM(reader)
	if err != nil {
		return err
	}

	reader = bytes.NewReader(kmBuf)
	km, err = ParseKM(reader)
	if err != nil {
		return err
	}

	acm, chipsets, processors, tpms, err, err2 = tools.ParseACM(acmBuf)
	if err != nil || err2 != nil {
		return err
	}

	if bpm != nil {
		fmt.Println(bpm.PrettyString(0, true))
	}
	if km != nil {
		fmt.Println(km.PrettyString(0, true))
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
	fitEntries, err := tools.ExtractFit(image)
	if err != nil {
		return err
	}
	fmt.Println("----Firmware Interface Table----")
	fmt.Println()
	for idx, entry := range fitEntries {
		fmt.Printf("Entry %d\n", idx)
		entry.FancyPrint()
		fmt.Println()
	}
	fmt.Println()
	return nil
}

// ParseFITEntries takes a firmware image and extract Boot policy manifest, key manifest and acm information.
func ParseFITEntries(image []byte) ([]byte, []byte, []byte, error) {
	fitEntries, err := tools.ExtractFit(image)
	if err != nil {
		return nil, nil, nil, err
	}
	var bpm, km, acm []byte
	reader := bytes.NewReader(image)
	for _, entry := range fitEntries {
		if entry.Type() == tools.BootPolicyManifest {
			if entry.Size() == 0 {
				return nil, nil, nil, fmt.Errorf("FIT entry size is zero for BPM")
			}
			addr, err := tools.CalcImageOffset(image, entry.Address)
			if err != nil {
				return nil, nil, nil, err
			}
			reader.Seek(int64(addr), io.SeekStart)
			bpm = make([]byte, entry.Size())
			len, err := reader.Read(bpm)
			if err != nil || uint32(len) != entry.Size() {
				return nil, nil, nil, err
			}
		}
		if entry.Type() == tools.KeyManifestRec {
			if entry.Size() == 0 {
				return nil, nil, nil, fmt.Errorf("FIT entry size is zero for KM")
			}
			addr, err := tools.CalcImageOffset(image, entry.Address)
			if err != nil {
				return nil, nil, nil, err
			}
			reader.Seek(int64(addr), io.SeekStart)
			km = make([]byte, entry.Size())
			len, err := reader.Read(km)
			if err != nil || uint32(len) != entry.Size() {
				return nil, nil, nil, err
			}
		}
		if entry.Type() == tools.StartUpACMod {
			addr, err := tools.CalcImageOffset(image, entry.Address)
			if err != nil {
				return nil, nil, nil, err
			}
			reader.Seek(int64(addr), io.SeekStart)
			if entry.Size() == 0 {
				buf := make([]byte, 32)
				_, err := reader.Read(buf)
				if err != nil {
					return nil, nil, nil, err
				}
				reader.Seek(int64(addr), io.SeekStart)
				size, err := tools.LookupACMSize(buf)
				if err != nil {
					return nil, nil, nil, err
				}
				acm = make([]byte, size)
				len, err := reader.Read(acm)
				if err != nil || int64(len) != size {
					return nil, nil, nil, err
				}
			} else {
				acm = make([]byte, entry.Size())
				len, err := reader.Read(acm)
				if err != nil || uint32(len) != entry.Size() {
					return nil, nil, nil, err
				}
			}
		}
	}
	if len(bpm) == 0 || len(km) == 0 || len(acm) == 0 {
		return nil, nil, nil, fmt.Errorf("Image has no BPM, KM, ACM")
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
	fitEntries, err := tools.ExtractFit(data)
	if err != nil {
		return nil, nil, err
	}
	var km *key.Manifest
	var bpm *bootpolicy.Manifest
	var acm *tools.ACM
	for _, entry := range fitEntries {
		if entry.Type() == tools.BootPolicyManifest {
			addr, err := tools.CalcImageOffset(data, entry.Address)
			if err != nil {
				return nil, nil, err
			}
			reader := bytes.NewReader(data)
			reader.Seek(int64(addr), io.SeekStart)
			bpm, err = ParseBPM(reader)
			if err != nil {
				return nil, nil, err
			}
		}
		if entry.Type() == tools.KeyManifestRec {
			addr, err := tools.CalcImageOffset(data, entry.Address)
			if err != nil {
				return nil, nil, err
			}
			reader := bytes.NewReader(data)
			reader.Seek(int64(addr), io.SeekStart)
			km, err = ParseKM(reader)
			if err != nil {
				return nil, nil, err
			}
		}
		if entry.Type() == tools.StartUpACMod {
			addr, err := tools.CalcImageOffset(data, entry.Address)
			if err != nil {
				return nil, nil, err
			}
			reader := bytes.NewReader(data)
			reader.Seek(int64(addr), io.SeekStart)
			buf := new(bytes.Buffer)
			buf.ReadFrom(reader)
			var err2 error
			acm, _, _, _, err, err2 = tools.ParseACM(buf.Bytes())
			if err != nil || err2 != nil {
				return nil, nil, err
			}
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
	fit := bytes.NewReader(image)
	hdr, err := tools.GetFitHeader(fit)
	if err != nil {
		return 0, err
	}
	totalSize += uint32(km.KeyManifestSignatureOffset)
	totalSize += keySignatureElementMaxSize
	totalSize += hdr.Size()
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
	fitEntries, err := tools.ExtractFit(image)
	if err != nil {
		return err
	}
	file, err := os.OpenFile(biosFilename, os.O_RDWR, 0600)
	if err != nil {
		return err
	}
	defer file.Close()
	for _, entry := range fitEntries {
		if entry.Type() == tools.BootPolicyManifest {
			if len(bpm) <= 0 {
				continue
			}
			if entry.Size() == 0 {
				return fmt.Errorf("FIT entry size is zero for BPM")
			}
			if len(bpm) > int(entry.Size()) {
				return fmt.Errorf("new BPM bigger than older BPM")
			}
			addr, err := tools.CalcImageOffset(image, entry.Address)
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
		}
		if entry.Type() == tools.KeyManifestRec {
			if len(km) <= 0 {
				continue
			}
			if entry.Size() == 0 {
				return fmt.Errorf("FIT entry size is zero for KM")
			}
			if len(km) > int(entry.Size()) {
				return fmt.Errorf("new KM bigger than older KM")
			}
			addr, err := tools.CalcImageOffset(image, entry.Address)
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
		}
		if entry.Type() == tools.StartUpACMod {
			if len(acm) <= 0 {
				continue
			}
			addr, err := tools.CalcImageOffset(image, entry.Address)
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
