package hwapi

import (
	"crypto"
	"crypto/sha1"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"

	tpm1 "github.com/google/go-tpm/tpm"
	tpm2 "github.com/google/go-tpm/tpm2"
	tpmutil "github.com/google/go-tpm/tpmutil"
)

// TCGVendorID TPM manufacturer id
type TCGVendorID uint32

func (id TCGVendorID) String() string {

	s, ok := vendors[id]
	if !ok {
		return fmt.Sprintf("unknown TPM vendor (%d)", id)
	}
	return s
}

var vendors = map[TCGVendorID]string{
	1095582720: "AMD",
	1096043852: "Atmel",
	1112687437: "Broadcom",
	1229081856: "IBM",
	1213220096: "HPE",
	1297303124: "Microsoft",
	1229346816: "Infineon",
	1229870147: "Intel",
	1279610368: "Lenovo",
	1314082080: "National Semiconductor",
	1314150912: "Nationz",
	1314145024: "Nuvoton Technology",
	1363365709: "Qualcomm",
	1397576515: "SMSC",
	1398033696: "ST Microelectronics",
	1397576526: "Samsung",
	1397641984: "Sinosun",
	1415073280: "Texas Instruments",
	1464156928: "Winbond",
	1380926275: "Fuzhou Rockchip",
	1196379975: "Google",
}

// PCR encapsulates the value of a PCR at a point in time.
type PCR struct {
	Index     int
	Digest    []byte
	DigestAlg crypto.Hash
}

// TPM interfaces with a TPM device on the system.
type TPM struct {
	Version TPMVersion
	Interf  TPMInterface

	SysPath string
	RWC     io.ReadWriteCloser
}

// probedTPM identifies a TPM device on the system, which
// is a candidate for being used.
type probedTPM struct {
	Version TPMVersion
	Path    string
}

// TPMInfo contains information about the version & interface
// of an open TPM.
type TPMInfo struct {
	Version      TPMVersion
	Interface    TPMInterface
	VendorInfo   string
	Manufacturer TCGVendorID

	// FirmwareVersionMajor and FirmwareVersionMinor describe
	// the firmware version of the TPM, but are only available
	// for TPM 2.0 devices.
	FirmwareVersionMajor int
	FirmwareVersionMinor int
}

// TPMVersion is used to configure a preference in
// which TPM to use, if multiple are available.
type TPMVersion uint8

// TPM versions
const (
	TPMVersionAgnostic TPMVersion = iota
	TPMVersion12
	TPMVersion20
)

// TPMInterface indicates how the client communicates
// with the TPM.
type TPMInterface uint8

// TPM interfaces
const (
	TPMInterfaceDirect TPMInterface = iota
	TPMInterfaceKernelManaged
	TPMInterfaceDaemonManaged
)

const (
	tpmRoot = "/sys/class/tpm"
)

func probeSystemTPMs() ([]probedTPM, error) {
	var tpms []probedTPM

	tpmDevs, err := ioutil.ReadDir(tpmRoot)
	if os.IsNotExist(err) {
		return nil, nil
	} else if err != nil {
		return nil, err
	}

	// TPM look up is hardcoded. Taken from googles go-attestation.
	// go-tpm does not support GetCapability with the required subcommand.
	// Implementation will be updated asap this is fixed in Go-tpm
	for _, tpmDev := range tpmDevs {
		if strings.HasPrefix(tpmDev.Name(), "tpm") {
			tpm := probedTPM{
				Path: filepath.Join(tpmRoot, tpmDev.Name()),
			}

			if _, err := os.Stat(filepath.Join(tpm.Path, "caps")); err != nil {
				if !os.IsNotExist(err) {
					return nil, err
				}
				tpm.Version = TPMVersion20
			} else {
				tpm.Version = TPMVersion12
			}
			tpms = append(tpms, tpm)
		}
	}

	return tpms, nil
}

func newTPM(pTPM probedTPM) (*TPM, error) {
	interf := TPMInterfaceDirect
	var rwc io.ReadWriteCloser
	var err error

	switch pTPM.Version {
	case TPMVersion12:
		devPath := filepath.Join("/dev", filepath.Base(pTPM.Path))
		interf = TPMInterfaceKernelManaged

		rwc, err = tpm1.OpenTPM(devPath)
		if err != nil {
			return nil, err
		}
	case TPMVersion20:
		// If the TPM has a kernel-provided resource manager, we should
		// use that instead of communicating directly.
		devPath := filepath.Join("/dev", filepath.Base(pTPM.Path))
		f, err := ioutil.ReadDir(filepath.Join(pTPM.Path, "device", "tpmrm"))
		if err != nil {
			if !os.IsNotExist(err) {
				return nil, err
			}
		} else if len(f) > 0 {
			devPath = filepath.Join("/dev", f[0].Name())
			interf = TPMInterfaceKernelManaged
		}

		rwc, err = tpm2.OpenTPM(devPath)
		if err != nil {
			return nil, err
		}
	}

	return &TPM{
		Version: pTPM.Version,
		Interf:  interf,
		SysPath: pTPM.Path,
		RWC:     rwc,
	}, nil
}

// MeasurementLog reads the TCPA eventlog in binary format
// from the Linux kernel
func (t *TPM) MeasurementLog() ([]byte, error) {
	return ioutil.ReadFile("/sys/kernel/security/tpm0/binary_bios_measurements")
}

func nvRead12(rwc io.ReadWriteCloser, index, offset, len uint32, auth string) ([]byte, error) {
	var ownAuth [20]byte //owner well known
	if auth != "" {
		ownAuth = sha1.Sum([]byte(auth))
	}

	// Get TPMInfo
	indexData, err := tpm1.GetNVIndex(rwc, index)
	if err != nil {
		return nil, err
	}
	if indexData == nil {
		return nil, fmt.Errorf("index not found")
	}

	// Check if authData is needed
	// AuthRead 0x00200000 | OwnerRead 0x00100000
	needAuthData := 1 >> (indexData.Permission.Attributes & (tpm1.NVPerAuthRead | tpm1.NVPerOwnerRead))
	authread := 1 >> (indexData.Permission.Attributes & tpm1.NVPerAuthRead)

	if needAuthData == 0 {
		if authread != 0 {
			return tpm1.NVReadValue(rwc, index, offset, len, ownAuth[:])
		}
		return tpm1.NVReadValue(rwc, index, offset, len, ownAuth[:])
	}
	return tpm1.NVReadValue(rwc, index, offset, len, nil)
}

func nvRead20(rwc io.ReadWriteCloser, index, authHandle tpmutil.Handle, password string, blocksize int) ([]byte, error) {
	return tpm2.NVReadEx(rwc, index, authHandle, password, blocksize)
}

func readTPM12Information(rwc io.ReadWriter) (TPMInfo, error) {

	manufacturerRaw, err := tpm1.GetManufacturer(rwc)
	if err != nil {
		return TPMInfo{}, err
	}

	manufacturerID := binary.BigEndian.Uint32(manufacturerRaw)
	return TPMInfo{
		VendorInfo:   TCGVendorID(manufacturerID).String(),
		Manufacturer: TCGVendorID(manufacturerID),
	}, nil
}

func readTPM20Information(rwc io.ReadWriter) (TPMInfo, error) {
	var vendorInfo string
	// The Vendor String is split up into 4 sections of 4 bytes,
	// for a maximum length of 16 octets of ASCII text. We iterate
	// through the 4 indexes to get all 16 bytes & construct vendorInfo.
	// See: TPM_PT_VENDOR_STRING_1 in TPM 2.0 Structures reference.
	uint32ToBytes := func(ui32 uint32) []byte {
		b := make([]byte, 4)
		binary.BigEndian.PutUint32(b, ui32)
		return b
	}

	for i := 0; i < 4; i++ {
		caps, _, err := tpm2.GetCapability(rwc, tpm2.CapabilityTPMProperties, 1, uint32(tpm2.VendorString1)+uint32(i))
		if err != nil {
			return TPMInfo{}, fmt.Errorf("tpm2.GetCapability(PT_VENDOR_STRING_%d) failed: %v", i+1, err)
		}
		subset, ok := caps[0].(tpm2.TaggedProperty)
		if !ok {
			return TPMInfo{}, fmt.Errorf("got capability of type %T, want tpm2.TaggedProperty", caps[0])
		}
		// Reconstruct the 4 ASCII octets from the uint32 value.
		vendorInfo += string(uint32ToBytes(subset.Value))
	}

	caps, _, err := tpm2.GetCapability(rwc, tpm2.CapabilityTPMProperties, 1, uint32(tpm2.Manufacturer))
	if err != nil {
		return TPMInfo{}, fmt.Errorf("tpm2.GetCapability(PT_MANUFACTURER) failed: %v", err)
	}
	manu, ok := caps[0].(tpm2.TaggedProperty)
	if !ok {
		return TPMInfo{}, fmt.Errorf("got capability of type %T, want tpm2.TaggedProperty", caps[0])
	}

	caps, _, err = tpm2.GetCapability(rwc, tpm2.CapabilityTPMProperties, 1, uint32(tpm2.FirmwareVersion1))
	if err != nil {
		return TPMInfo{}, fmt.Errorf("tpm2.GetCapability(PT_FIRMWARE_VERSION_1) failed: %v", err)
	}
	fw, ok := caps[0].(tpm2.TaggedProperty)
	if !ok {
		return TPMInfo{}, fmt.Errorf("got capability of type %T, want tpm2.TaggedProperty", caps[0])
	}

	return TPMInfo{
		VendorInfo:           strings.Trim(vendorInfo, "\x00"),
		Manufacturer:         TCGVendorID(manu.Value),
		FirmwareVersionMajor: int((fw.Value & 0xffff0000) >> 16),
		FirmwareVersionMinor: int(fw.Value & 0x0000ffff),
	}, nil
}

func getCapability12(rwc io.ReadWriteCloser, cap, subcap uint32) ([]byte, error) {
	return tpm1.GetCapabilityRaw(rwc, cap, subcap)
}

func getCapability20(rwc io.ReadWriteCloser, cap tpm2.Capability, subcap uint32) ([]byte, error) {
	return nil, fmt.Errorf("not yet supported by tss")
}

func readNVPublic12(rwc io.ReadWriteCloser, index uint32) ([]byte, error) {
	return tpm1.GetCapabilityRaw(rwc, tpm1.CapNVIndex, index)
}

func readNVPublic20(rwc io.ReadWriteCloser, index uint32) ([]byte, error) {
	data, err := tpm2.NVReadPublic(rwc, tpmutil.Handle(index))
	if err != nil {
		return nil, err
	}
	return tpmutil.Pack(data)
}

func readAllPCRs20(tpm io.ReadWriter, alg tpm2.Algorithm) (map[uint32][]byte, error) {
	numPCRs := 24
	out := map[uint32][]byte{}

	// The TPM 2.0 spec says that the TPM can partially fulfill the
	// request. As such, we repeat the command up to 8 times to get all
	// 24 PCRs.
	for i := 0; i < numPCRs; i++ {
		// Build a selection structure, specifying all PCRs we do
		// not have the value for.
		sel := tpm2.PCRSelection{Hash: alg}
		for pcr := 0; pcr < numPCRs; pcr++ {
			if _, present := out[uint32(pcr)]; !present {
				sel.PCRs = append(sel.PCRs, pcr)
			}
		}

		// Ask the TPM for those PCR values.
		ret, err := tpm2.ReadPCRs(tpm, sel)
		if err != nil {
			return nil, fmt.Errorf("tpm2.ReadPCRs(%+v) failed with err: %v", sel, err)
		}
		// Keep track of the PCRs we were actually given.
		for pcr, digest := range ret {
			out[uint32(pcr)] = digest
		}
		if len(out) == numPCRs {
			break
		}
	}

	if len(out) != numPCRs {
		return nil, fmt.Errorf("failed to read all PCRs, only read %d", len(out))
	}

	return out, nil
}

func readAllPCRs12(rwc io.ReadWriter) (map[uint32][]byte, error) {
	numPCRs := 24
	out := map[uint32][]byte{}

	for i := 0; i < numPCRs; i++ {
		// Ask the TPM for those PCR values.
		pcr, err := tpm1.ReadPCR(rwc, uint32(i))
		if err != nil {
			return nil, fmt.Errorf("tpm.ReadPCR(%d) failed with err: %v", i, err)
		}
		out[uint32(i)] = pcr
		if len(out) == numPCRs {
			break
		}
	}

	if len(out) != numPCRs {
		return nil, fmt.Errorf("failed to read all PCRs, only read %d", len(out))
	}

	return out, nil
}

func readPCR12(rwc io.ReadWriter, pcrIndex uint32) ([]byte, error) {
	return tpm1.ReadPCR(rwc, pcrIndex)
}

func readPCR20(rwc io.ReadWriter, pcrIndex uint32) ([]byte, error) {
	return tpm2.ReadPCR(rwc, int(pcrIndex), tpm2.AlgSHA256)
}

// NewTPM returns a TPM
func NewTPM() (*TPM, error) {
	candidateTPMs, err := probeSystemTPMs()
	if err != nil {
		return nil, err
	}

	for _, tpm := range candidateTPMs {
		tss, err := newTPM(tpm)
		if err != nil {
			continue
		}
		return tss, nil
	}

	return nil, errors.New("TPM device not available")
}

// Info returns information about the TPM.
func (t *TPM) Info() (*TPMInfo, error) {
	var info TPMInfo
	var err error
	switch t.Version {
	case TPMVersion12:
		info, err = readTPM12Information(t.RWC)
	case TPMVersion20:
		info, err = readTPM20Information(t.RWC)
	default:
		return nil, fmt.Errorf("unsupported TPM version: %x", t.Version)
	}
	if err != nil {
		return nil, err
	}

	return &info, nil
}

// GetVersion returns the TPM version
func (t *TPM) GetVersion() TPMVersion {
	return t.Version
}

// Close closes the TPM socket and wipe locked buffers
func (t *TPM) Close() error {
	return t.RWC.Close()
}

// NVReadValue reads a value from a given NVRAM index
// Type and byte order for TPM1.2 interface:
// (offset uint32)
// Type and byte oder for TPM2.0 interface:
// (authhandle uint32)
func (t *TPM) NVReadValue(index uint32, ownerPassword string, size, offhandle uint32) ([]byte, error) {
	switch t.Version {
	case TPMVersion12:
		return nvRead12(t.RWC, index, offhandle, size, ownerPassword)
	case TPMVersion20:
		return nvRead20(t.RWC, tpmutil.Handle(index), tpmutil.Handle(offhandle), ownerPassword, int(size))
	}
	return nil, fmt.Errorf("unsupported TPM version: %x", t.Version)
}

// GetCapability requests the TPMs capability function and returns an interface.
// User needs to take care of the data for now.
func (t *TPM) GetCapability(cap, subcap uint32) ([]interface{}, error) {
	var err error
	var b []byte
	var ret []interface{}
	switch t.Version {
	case TPMVersion12:
		b, err = getCapability12(t.RWC, cap, subcap)
	case TPMVersion20:
		b, err = getCapability20(t.RWC, tpm2.Capability(cap), subcap)
	default:
		return nil, fmt.Errorf("unsupported TPM version: %x", t.Version)
	}
	if err != nil {
		return nil, err
	}
	ret = append(ret, b)
	return ret, nil
}

// ReadNVPublic reads public data about an NVRAM index. Permissions and what so not.
func (t *TPM) ReadNVPublic(index uint32) ([]byte, error) {
	var raw []byte
	var err error
	switch t.Version {
	case TPMVersion12:
		raw, err = readNVPublic12(t.RWC, index)
		if err != nil {
			return nil, err
		}
		return raw, nil
	case TPMVersion20:
		raw, err = readNVPublic20(t.RWC, index)
		if err != nil {
			return nil, err
		}
	default:
		return nil, fmt.Errorf("unsupported TPM version %v", t.Version)
	}

	return raw, nil
}

// ReadPCRs reads all PCRs into the PCR structure
func (t *TPM) ReadPCRs(alg tpm2.Algorithm) ([]PCR, error) {
	var PCRs map[uint32][]byte
	var err error

	switch t.Version {
	case TPMVersion12:
		if alg != tpm2.AlgSHA1 {
			return nil, fmt.Errorf("non-SHA1 algorithm %v is not supported on TPM 1.2", alg)
		}
		PCRs, err = readAllPCRs12(t.RWC)
		if err != nil {
			return nil, fmt.Errorf("failed to read PCRs: %v", err)
		}

	case TPMVersion20:
		PCRs, err = readAllPCRs20(t.RWC, alg)
		if err != nil {
			return nil, fmt.Errorf("failed to read PCRs: %v", err)
		}

	default:
		return nil, fmt.Errorf("unsupported TPM version: %x", t.Version)
	}

	out := make([]PCR, len(PCRs))
	for index, digest := range PCRs {
		h, err := alg.Hash()
		if err != nil {
			return nil, err
		}
		out[int(index)] = PCR{
			Index:     int(index),
			Digest:    digest,
			DigestAlg: h,
		}
	}

	return out, nil
}

// ReadPCR reads a single PCR value by defining the pcrIndex
func (t *TPM) ReadPCR(pcrIndex uint32) ([]byte, error) {
	switch t.Version {
	case TPMVersion12:
		return readPCR12(t.RWC, pcrIndex)
	case TPMVersion20:
		return readPCR20(t.RWC, pcrIndex)
	default:
		return nil, fmt.Errorf("unsupported TPM version: %x", t.Version)
	}
}
