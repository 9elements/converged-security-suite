Intel BtG/CBnT Provisioning
===============================

This Golang utility supports the artifact generation to support Intel BootGuard and Trustes Execution Technology (CBnT)

Prerequisites for Usage
-----------------------
Supported OS: Any Linux distribution

How to compile
-----------------------

Get Golang >= 1.11 and export:
```
export GO111MODULE=on
```
or set it in front of every command.
This environment variable actives moduled for GO 1.11

To download all dependencies run:
```
<GO111MODULE=on> go mod download
```

Verify all downloaded dependencies run:
```
<GO111MODULE=on> go mod verify
```

To build the test suite run:

```
<GO111MODULE=on> go build -o bg-prov cmd/bg-prov/*.go
```

Commandline subcommands:
--------------
```bash
Usage: bg-prov <command>

Intel BtG/CBnT provisioning tooling

Flags:
  -h, --help                           Show context-sensitive help.
      --debug                          Enable debug mode.
      --manifest-strict-order-check    Enable checking of manifest elements order

Commands:
  km-show         Prints Key Manifest binary in human-readable format
  km-gen-v-1      Generate v1 KM file based von json configuration
  km-gen-v-2      Generate v2 KM file based von json configuration
  km-sign         Sign key manifest with given key
  km-verify       Verify the signature of a given KM
  km-stitch       Stitches KM Signatue into unsigned KM
  km-export       Exports KM structures from BIOS image into file
  bpm-show        Prints Boot Policy Manifest binary in human-readable format
  bpm-gen-v-1     Generate v1 BPM file based von json configuration
  bpm-gen-v-2     Generate v2 BPM file based von json configuration
  bpm-sign        Sign Boot Policy Manifest with given key
  bpm-verify      Verify the signature of a given KM
  bpm-stitch      Stitches BPM Signatue into unsigned BPM
  bpm-export      Exports BPM structures from BIOS image into file
  acm-gen-v-0     Generate an ACM v0 module (usable only for unit-tests)
  acm-gen-v-3     Generate an ACM v3 module (usable only for unit-tests)
  acm-export      Exports ACM structures from BIOS image into file
  acm-show        Prints ACM binary in human-readable format
  fit-show        Prints the FIT Table of given BIOS image file
  show-all        Prints BPM, KM, FIT and ACM from BIOS binary in human-readable format
  stitch          Stitches BPM, KM and ACM into given BIOS image file
  key-gen         Generates key for KM and BPM signing
  template-v-1    Writes template v1 JSON configuration into file
  template-v-2    Writes template v2 JSON configuration into file
  read-config     Reads config from existing BIOS file and translates it to a JSON configuration
  version         Prints the version of the program

Run "bg-prov <command> --help" for more information on a command.

bg-prov: error: expected one of "km-show",  "km-gen-v-1",  "km-gen-v-2",  "km-sign",  "km-verify",  ...
```

Workflows
==========

I. Boot Policy / Key Manifest Generation/Signing/Stitching
-------------------------------

1. Create a template config file
```bash
./bg-prov template ./config.json
```

2. Create keys for signing of Key Manifest (KM) and Boot Policy Manifest (BPM)
Algorithm: RSA, BitSize: 2048, no password for enryption of private key files
```bash
./bg-prov key-gen RSA2048 "" --path=./Keys/mykey
```

3. Generate Key Manifest (KM)
```bash
./bg-prov km-gen-v-2 ./KM/km_unsigned.bin ./Keys/mykey_km_pub.pem \
        --config=./config.json \
        --pkhashalg=12 \
        --bpmpubkey=./Keys/mykey_bpmpub.pem \
        --bpmhashalgo=12
```

4. Generation of Boot Policy Manifest (BPM)
```bash
./bg-prov bpm-gen-v-2 ./BPM/bpm_unsigned.bin ./firmware.rom --config=./config.json
```

5. Sign Key Manifest (KM)
```bash
./bg-prov km-sign ./KM/km_unsigned.bin ./KM/km_signed.bin ./Keys/myKey_km_priv.pem ""
```

6. Sign Boot Policy Manifest (BPM)
```bash
./bg-prov bpm-sign ./BPM/bpm_unsigned.bin ./BPM/bpm_signed.bin ./Keys/myKey_bpm_priv.pem ""

```

7. Export ACM for stitching (Firmware image must contain an ACM)
Skip this if you already have an ACM for stitching
```bash
./bg-prov export-acm ./firmware.rom ./ACM/acm_export.bin
```

8. Stitch BPM, KM and ACM into firmware image
```bash
./bg-prov stitch ./firmware.rom ./ACM/acm.bin ./KM/km_signed.bin ./BPM/bpm_signed.bin
```

II. Read config from a CBnT enabled firmware image
-------------------------------------------
```bash
./bg-prov read-config ./config.json ./firmware.rom
```

III Export KM, BPM and ACM from CBnT enabled firmware image
------------------------------------------------
1. Export of KM
```bash
./bg-prov export-km ./firmware.rom ./KM/km_export.bin
```

2. Export BPM
```bash
./bg-prov export-km ./firmware.rom ./BPM/bpm_export.bin
```

3. Export ACM
```bash
./bg-prov export-acm ./firmware.rom ./ACM/acm_export.bin
```

IV. Show details of exported KM, BPM, ACM
--------------------------------------
1. Show details of KM
```bash
./bg-prov show-km ./KM/km_signed.bin
```

2. Show details of BPM
```bash
./bg-prov show-bpm ./BPM/bpm_signed.bin
```

3. Show details of ACM
```bash
./bg-prov show-acm ./ACM/acm_signed.bin
```

4. Show all 
```bash
./bg-prov show-all ./firmware.rom
```
