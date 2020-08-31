package main

import (
	"crypto/sha1"
	"crypto/sha256"
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"os"
	"strconv"
	"strings"

	"github.com/9elements/converged-security-suite/pkg/tools"

	prov "github.com/9elements/converged-security-suite/pkg/provisioning"
)

var (
	// Flags
	deleteAUX     = flag.Bool("dAUX", false, "Overwrites PS index, so that AUX index will be deleted after next restart of the system.")
	deletePS      = flag.Bool("dPS", false, "Deletes PS index. Only use AFTER -dAUX and restarting the system!!")
	provi         = flag.Bool("prov", false, "Needs to be set to provision the PS and AUX index")
	loadfiles     = flag.Bool("lf", false, "Loads hashes from working directory with repective names: del.<HashAlg>', 'write.<HashAlg>', 'psPolicy.<HashAlg>'")
	passwordWrite = flag.String("pWrite", "keins", "Enter a password for writing the PS index. Default: 'keins'")
	passwordDel   = flag.String("pDelete", "keins", "Enter a password for deleting the PS index. Default: 'keins'")
	savePol       = flag.Bool("s", false, "Select if policies shall be saved in a file. Default: false")
	tpm           = flag.String("tpm", "/dev/tpm", "Select a path to a tpm device")
	help          = flag.Bool("h", false, "Shows help")
	version       = flag.Bool("v", false, "Shows version and license information")
	pslcpfile     = flag.String("lcp", "pslcp.json", "Provide a json filename with LCP configuration. Default: psLCP.json")
)

func showVersion() {
	fmt.Println("Converged Security Suite TXT provisioning tool")
	fmt.Println("")
	fmt.Println("BSD 3-Clause License")
	fmt.Println("")
	fmt.Println("Copyright (c) 2020, 9elements GmbH.")
	fmt.Println("Copyright (c) 2020, facebook Inc.")
	fmt.Println("All rights reserved.")
}

func showHelp() {
	fmt.Println("Converged Security Suite TXT provisioning tool")
	fmt.Println("Usage: prov-tools -lf [-dAUX -pwWrite][-dPS -pwDelete][-hash SHAXXX][-h][-v]")
	fmt.Println("\t-dAUX [-pwDelete=<password>] | [-lf]          : Overwrites PS index with AUXdelete bit set. Needs a reboot afterwards.")
	fmt.Println("\t-dPS [-pwDelete=<password>] | [-lf]           : Delete PS index. Only permitted after using -dAUX and a reboot.")
	fmt.Println("\t-hash [SHA1] | [SHA256] | [SHA384] | [SHA512] : Select a hash algorithms for creating the policy. Supported: SHA1(TPM 1.2 only), SHA256(TPM 2.0 default), SHA384, SHA512")
	fmt.Println("\t[-lf]                                         : Loads files named 'del.<HashAlg>', 'write.<HashAlg>', 'psPolicy.<HashAlg>' from the working directory")
	fmt.Println("\t[-pWrite=<password>]                          : Give a passwort for write branch of PS policy")
	fmt.Println("\t[-pDelete=<password>]                         : Give a passwort for delete branch of PS policy")
	fmt.Println("\t-lcp <filename.json>							 : Give a filename for the LCP configuration in json format.")
	fmt.Println("\t-s                                            : Select if policies shall be safed. Default: false")
	fmt.Println("\t-h                                            : Shows this help")
	fmt.Println("\t-v                                            : Shows version and license information")
	fmt.Println("")
	fmt.Println("The tool writes hashes to files named 'del.<HashAlg>', 'write.<HashAlg>', 'psPolicy.<HashAlg>'")
}

func handlePasswordsTPM20() (*[32]byte, *[32]byte, error) {
	var pDh, pWh [32]byte
	if *passwordWrite != "" && *passwordDel != "" {
		pDh = sha256.Sum256([]byte(*passwordDel))
		pWh = sha256.Sum256([]byte(*passwordWrite))
		return &pDh, &pWh, nil
	}
	return nil, nil, fmt.Errorf("Password is empty")
}

func handlePasswordsTPM12() ([20]byte, [20]byte) {
	return sha1.Sum([]byte(*passwordDel)), sha1.Sum([]byte(*passwordWrite))
}

func writeFile(name string, hash [32]byte) error {
	file, err := os.Create(name)
	if err != nil {
		return err
	}
	defer file.Close()
	file.WriteString(string(hash[:32]))
	return nil
}

func loadFilesSHA256() (*[32]byte, *[32]byte, *[32]byte, error) {
	var delHash [32]byte
	var writeHash [32]byte
	var psPolicy [32]byte
	files, err := ioutil.ReadDir(".")
	if err != nil {
		return nil, nil, nil, err
	}
	for _, file := range files {
		var data []byte
		f, err := os.Open(file.Name())
		if err != nil {
			return nil, nil, nil, err
		}
		_, err = f.Read(data)
		if err != nil {
			return nil, nil, nil, err
		}
		if strings.Contains(file.Name(), "delHash") {
			copy(delHash[:], data[:32])
		}
		if strings.Contains(file.Name(), "writeHash") {
			copy(writeHash[:], data[:32])
		}
		if strings.Contains(file.Name(), "psPolicy") {
			copy(psPolicy[:], data[:32])
		}
	}
	return &delHash, &writeHash, &psPolicy, nil
}

func getLCPDataFromFile() (*tools.LCPPolicy2, error) {
	var ok bool
	var b []byte
	b, err := ioutil.ReadFile(*pslcpfile)
	if err != nil {
		return nil, err
	}
	lcpdata, err := parseLCP2File(b)
	if err != nil {
		return nil, err
	}
	ver, err := strconv.ParseUint(lcpdata.Version, 0, 0)
	if err != nil {
		return nil, err
	}
	if uint16(ver) < uint16(0x300) || uint16(ver) > uint16(0x306) {
		return nil, fmt.Errorf("Invalid LCP Version. Want: 0x302 - 0x306 - Have: %v", lcpdata.Version)
	}

	hashAlg, ok := tools.HashAlgMap[prov.HashMapping[lcpdata.HashAlg]]
	if ok == false {
		return nil, fmt.Errorf("Cant determin hash algorithm")
	}

	pT, err := strconv.ParseUint(lcpdata.PolicyType, 0, 0)
	if err != nil {
		return nil, err
	}
	if tools.LCPPolicyType(pT) > tools.LCPPolicyTypeAny && tools.LCPPolicyType(pT) < tools.LCPPolicyTypeList {
		return nil, fmt.Errorf("Invalid PolicyType. Want: 0(Signed Policy) or 1 (Auto promotion) - Have: %v", lcpdata.PolicyType)
	}

	smv, err := strconv.ParseUint(lcpdata.SINITMinVersion, 0, 0)
	if err != nil {
		return nil, err
	}

	s1 := strings.Split(lcpdata.LcpSignAlgMask, ",")
	var s1val tools.LCPPol2Sig
	for _, item := range s1 {
		s1val += tools.SignMaskMap[item]
	}

	s2 := strings.Split(lcpdata.LcpHashAlgMask, ",")
	var s2val uint16
	for _, item := range s2 {
		s2val += tools.HashMaskMap[item]
	}

	s3 := strings.Split(lcpdata.PolicyControl, ",")
	var s3val uint32
	for _, item := range s3 {
		s3val += tools.PolicyControlMap[item]
	}
	// Fixed SHA256 use
	hash := make([]byte, 32)
	for iterator := range hash {
		hash[iterator] = byte(iterator)
	}

	lcppol := tools.LCPPolicy2{
		Version:                uint16(ver),
		HashAlg:                hashAlg,
		PolicyType:             tools.LCPPolicyType(pT),
		SINITMinVersion:        uint8(smv),
		DataRevocationCounters: [8]uint16{0, 0, 0, 0, 0, 0, 0, 0},
		PolicyControl:          s3val,
		MaxSINITMinVersion:     uint8(0),
		Reserved:               uint8(0),
		LcpHashAlgMask:         s2val,
		LcpSignAlgMask:         s1val,
		Reserved2:              uint32(0),
		PolicyHash:             hash,
	}
	lcppol.PrettyPrint()
	return &lcppol, nil
}

func parseLCP2File(data []byte) (*prov.LCP2ConfigJSON, error) {
	var lcp2Data prov.LCP2ConfigJSON
	if err := json.Unmarshal(data, &lcp2Data); err != nil {
		return nil, err
	}
	return &lcp2Data, nil
}
