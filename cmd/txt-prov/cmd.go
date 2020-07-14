package main

import (
	"crypto"
	"crypto/sha1"
	"flag"
	"fmt"
	"io/ioutil"
	"os"
	"strings"

	prov "github.com/9elements/converged-security-suite/pkg/provisioning"
)

var (
	// Flags
	deleteAUX     = flag.Bool("-dAUX", false, "Overwrites PS index, so that AUX index will be deleted after next restart of the system.")
	deletePS      = flag.Bool("-dPS", false, "Deletes PS index. Only use AFTER -dAUX and restarting the system!!")
	provi         = flag.Bool("-prov", false, "Needs to be set to provision the PS and AUX index")
	hashAlg       = flag.String("hash", "SHA256", "Select one or more hash algorithms for creation of policies. Default: SHA1(TPM 1.2) / SHA256(TPM 2.0")
	loadfiles     = flag.Bool("lf", false, "Loads hashes from working directory with repective names: del.<HashAlg>', 'write.<HashAlg>', 'psPolicy.<HashAlg>'")
	passwordWrite = flag.String("pWrite", "none", "Enter a password for writing the PS index. Default: 'none'")
	passwordDel   = flag.String("pDelete", "none", "Enter a password for deleting the PS index. Default: 'none'")
	savePol       = flag.Bool("s", false, "Select if policies shall be saved in a file. Default: false")
	help          = flag.Bool("h", false, "Shows help")
	version       = flag.Bool("v", false, "Shows version and license information")
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
	fmt.Println("\t-s                                            : Select if policies shall be safed. Default: false")
	fmt.Println("\t-h                                            : Shows this help")
	fmt.Println("\t-v                                            : Shows version and license information")
	fmt.Println("")
	fmt.Println("The tool writes hashes to files named 'del.<HashAlg>', 'write.<HashAlg>', 'psPolicy.<HashAlg>'")
}

func handlePasswordsTPM20(hashAlg crypto.Hash) ([]byte, []byte, error) {
	hA := hashAlg.New()
	if *passwordWrite != "" && *passwordDel != "" {
		return hA.Sum([]byte(*passwordDel)), hA.Sum([]byte(*passwordWrite)), nil
	}
	return nil, nil, fmt.Errorf("Password is empty")
}

func handlePasswordsTPM12() ([20]byte, [20]byte) {
	return sha1.Sum([]byte(*passwordDel)), sha1.Sum([]byte(*passwordWrite))
}

func deconstructHashesAlg() (*crypto.Hash, error) {
	h, a := prov.HashMapping[*hashAlg]
	if a == true {
		return &h, nil
	}
	return nil, fmt.Errorf("Hash algorithm not found. Need SHA256, SHA384 or SHA512")

}

func writeFile(name string, hash []byte, hashAlg crypto.Hash) error {
	file, err := os.Create(name + "." + string(hashAlg))
	if err != nil {
		return err
	}
	defer file.Close()
	file.WriteString(string(hash))
	return nil
}

func loadFiles() ([]byte, []byte, []byte, *crypto.Hash, error) {
	var hAlg *crypto.Hash
	var delHash []byte
	var writeHash []byte
	var psPolicy []byte
	files, err := ioutil.ReadDir(".")
	if err != nil {
		return nil, nil, nil, nil, err
	}
	for _, file := range files {
		var data []byte
		if strings.HasSuffix(file.Name(), ".SHA256") {
			*hAlg = crypto.SHA256
			data = make([]byte, crypto.SHA256)
		} else {
			continue
		}
		f, err := os.Open(file.Name())
		if err != nil {
			return nil, nil, nil, nil, err
		}
		_, err = f.Read(data)
		if err != nil {
			return nil, nil, nil, nil, err
		}
		if strings.Contains(file.Name(), "delHash") {
			delHash = data
		}
		if strings.Contains(file.Name(), "writeHash") {
			writeHash = data
		}
		if strings.Contains(file.Name(), "psPolicy") {
			psPolicy = data
		}
	}
	return delHash, writeHash, psPolicy, hAlg, nil
}
