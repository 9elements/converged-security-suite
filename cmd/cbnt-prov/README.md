Intel CBnT Provisioning
===============================

This Golang utility supports the artifact generation to support Intel Converged BootGuard and Trustes Execution Technology (CBnT)

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
<GO111MODULE=on> go build -o txt-suite cmd/cbnt-prov/*.go
```

Commandline subcommands:
--------------
```bash
Usage of ./cbnt-prov:
    version        
            Prints the version of the program
    show-km   
            Prints Key Manifest binary in human-readable format
    show-bpm
            Prints Boot Policy Manifest binary in human-readable format
    show-acm    
            Prints ACM binary in human-readable format
    show-all   
            Prints BPM, KM, FIT and ACM from BIOS binary in human-readable format
    export-acm   
            Exports ACM structures from BIOS image into file
    export-km   
            Exports KM structures from BIOS image into file
    export-bpm  
            Exports BPM structures from BIOS image into file
    template   
            Writes template JSON configuration into file
    read-config 
            Reads config from existing BIOS file and translates it to a JSON configuration
    km-gen       
            Generate KM file based on json configuration
    bpm-gen    
            Generate BPM file based on json configuration
    km-sign    
            Sign key manifest with given key
    bpm-sign       
            Sign Boot Policy Manifest with given key
    stitch    
            Stitches BPM, KM and ACM into given BIOS image file
    key-gen   
            Generates key for KM and BPM signing

Flags:
    --help (-h)
            Prints more information about ./cbnt-prov
```
Every subcommand has several required or optional arguments and flags. To learn more about them:
```bash
./cbnt-prov <subcommand> -h
```

Extended documentation about subcommands:
--------------

```bash
./cbnt-prov show-km       Prints Key Manifest binary in human-readable format
        <path>  Path to binary file containing Key Manifest
```

```bash
./cbnt-prov show-bpm      Prints Boot Policy Manifest binary in human-readable format
        <path>  Path to binary file containing Boot Policy Manifest
```
    
```bash
./cbnt-prov show-acm      Prints ACM binary in human-readable format
        <path>  Path to binary file containing Authenticated Code Module (ACM)
```

```bash
./cbnt-prov show-all      Prints BPM, KM, FIT and ACM from Firmware image binary in human-readable format
        <path>  Path to full Firmaware image binary file containing Key Manifest, Boot Policy Manifest and ACM
```
    
```bash 
./cbnt-prov export-acm    Exports ACM binary from Firmware image into file
        <bios>    Path to the full Firmware image binary file.
        <out>     Path to the newly generated ACM binary file.
```
   
```bash
./cbnt-prov export-km     Exports KM structures from Firmware image image into file
        <bios>    Path to the full Firmware image binary file.
        <out>     Path to the newly generated Key Manifest binary file.
```
    
```bash
./cbnt-prov export-bpm    Exports BPM structures from Firmware image image into file
        <bios>    Path to the full Firmware image binary file.
        <out>     Path to the newly generated Boot Policy Manifest binary file.
```
 
```bash
./cbnt-prov read-config   Reads config from existing BIOS file and translates it to a JSON configuration
        <config>    Path to the JSON config file.
        <bios>      Path to the full Firmware image binary file.
```

        
```bash
./cbnt-prov km-gen        Generate KM file based of json configuration
        <km>     Path to the newly generated Key Manifest binary file.
        <key>    Public Boot Policy signing key

        --config=STRING                  Path to the JSON config file.
        --revision=UINT-8                Platform Manufacturer’s BPM revision number.
        --svn=UINT-8                     Boot Policy Manifest Security Version Number
        --id=UINT-8                      The key Manifest Identifier
        --pkhashalg=UINT-16              Hash algorithm of OEM public key digest
        --bpmpubkey=STRING               Path to bpm public signing key
        --bpmhashalgo=ALGORITHM          Hash algorithm for bpm public signing key
        --out=STRING                     Path to write applied config to
        --cut                            Cuts the signature before writing to binary (Facebook requirement)
```
 
```bash
./cbnt-prov bpm-gen             Generate BPM file based of json configuration and complete firmware image
        <bpm>                 Path to the newly generated Boot Policy Manifest binary file.
        <bios>                Path to the firmware image binary file.
        
        --config              Path to the JSON config file.

        --revision            Platform Manufacturer’s BPM revision number.
        --svn                 Boot Policy Manifest Security Version Number
        --acmsvn              Authorized ACM Security Version Number
        --nems                Size of data region need by IBB expressed in 4K pages. 
                              E.g., value of 1 = 4096 bytes; 2 = 8092 bytes, etc. Must not be zero
        --pbet                Protect BIOS Environment Timer (PBET) value.
        --ibbflags            IBB Control flags
        --mchbar              MCHBAR address
        --vdtbar              VTDPVC0BAR address
        --dmabase0            Low DMA protected range base
        --dmasize0            Low DMA protected range limit
        --dmabase1            High DMA protected range base.
        --dmasize1            High DMA protected range limit.
        --entrypoint          IBB (Startup BIOS) entry point
        --sintmin             OEM authorized SinitMinSvn value
        --txtflags            TXT Element control flags
        --powerdowninterval   Duration of Power Down in 5 sec increments
        --acpibaseoffset      ACPI IO offset.
        --powermbaseoffset    ACPI MMIO offset.
        --cmosoff0            CMOS byte in bank 0 to store platform wakeup time
        --cmosoff1            Second CMOS byte in bank 0 to store platform wakeup time

        --out                 Path to write applied config to
```
     
```bash
./cbnt-prov km-sign       Sign key manifest with given key
        <km-in>         Path to the generated Key Manifest binary file.
        <km-out>        Path to write the signed KM to
        <km-keyfile>    Path to the encrypted PKCS8 private key file.
        <password>      Password to decrypted PKCS8 private key file
```
      
```bash
./cbnt-prov bpm-sign      Sign Boot Policy Manifest with given key
        <bpm-in>         Path to the newly generated Boot Policy Manifest binary file.
        <bpm-out>       Path to write the signed BPM to
        <bpm-keyfile>   Path to the encrypted PKCS8 private key file.
        <password>      Password to decrypt PKCS8 private key file
```
        
```bash
./cbnt-prov stitch   Stitches BPM, KM and ACM into given BIOS image file     
        <bios>     Path to the full BIOS binary file.
        [<acm>]    Path to the ACM binary file.
        [<km>]     Path to the Key Manifest binary file.
        [<bpm>]    Path to the Boot Policy Manifest binary file.
```
      
```bash
./cbnt-prov key-gen               Generates key for KM and BPM signing
        <algo>                  Select crypto algorithm for key generation. Options: RSA2048. RSA3072, ECC224, ECC256
        <password>              Password for AES256 encryption of private keys
        [<path>]                Path to store keys. 
                                File names are '<path>_bpm/.pub' and '<path>_km/.pub' respectivly
```

     
```bash
./cbnt-prov template                       Writes template JSON configuration into file
        <path>                   Path to the newly generated JSON configuration file.

        --revision            Platform Manufacturer’s BPM revision number.
        --svn                 Boot Policy Manifest Security Version Number
        --acmsvn              Authorized ACM Security Version Number
        --nems                Size of data region need by IBB expressed in 4K pages. 
                              E.g., value of 1 = 4096 bytes; 2 = 8092 bytes, etc. Must not be zero
        --pbet                Protect BIOS Environment Timer (PBET) value.
        --ibbflags            IBB Control flags
        --mchbar              MCHBAR address
        --vdtbar              VTDPVC0BAR address
        --dmabase0            Low DMA protected range base
        --dmasize0            Low DMA protected range limit
        --dmabase1            High DMA protected range base.
        --dmasize1            High DMA protected range limit.
        --entrypoint          IBB (Startup BIOS) entry point
        --sintmin             OEM authorized SinitMinSvn value
        --txtflags            TXT Element control flags
        --powerdowninterval   Duration of Power Down in 5 sec increments
        --acpibaseoffset      ACPI IO offset.
        --powermbaseoffset    ACPI MMIO offset.
        --cmosoff0            CMOS byte in bank 0 to store platform wakeup time
        --cmosoff1            Second CMOS byte in bank 0 to store platform wakeup time
```

Workflows
==========

I. Boot Policy / Key Manifest Generation/Signing/Stitching
-------------------------------

1. Create a template config file
```bash
./cbnt-prov template ./config.json
```

2. Create keys for signing of Key Manifest (KM) and Boot Policy Manifest (BPM)
Algorithm: RSA, BitSize: 2048, no password for enryption of private key files
```bash
./cbnt-prov key-gen RSA2048 "" --path=./Keys/mykey
```

3. Generate Key Manifest (KM)
```bash
./cbnt-prov km-gen ./KM/km_unsigned.bin ./Keys/mykey_km_pub.pem \
        --config=./config.json \
        --pkhashalg=12 \
        --bpmpubkey=./Keys/mykey_bpmpub.pem \
        --bpmhashalgo=12
```

4. Generation of Boot Policy Manifest (BPM)
```bash
./cbnt-prov bpm-gen ./BPM/bpm_unsigned.bin ./firmware.rom --config=./config.json
```

5. Sign Key Manifest (KM)
```bash
./cbnt-prov km-sign ./KM/km_unsigned.bin ./KM/km_signed.bin ./Keys/myKey_km_priv.pem ""
```

6. Sign Boot Policy Manifest (BPM)
```bash
./cbnt-prov bpm-sign ./BPM/bpm_unsigned.bin ./BPM/bpm_signed.bin ./Keys/myKey_bpm_priv.pem ""

```

7. Export ACM for stitching (Firmware image must contain an ACM)
Skip this if you already have an ACM for stitching
```bash
./cbnt-prov export-acm ./firmware.rom ./ACM/acm_export.bin
```

8. Stitch BPM, KM and ACM into firmware image
```bash
./cbnt-prov stitch ./firmware.rom ./ACM/acm.bin ./KM/km_signed.bin ./BPM/bpm_signed.bin
```

II. Read config from a CBnT enabled firmware image
-------------------------------------------
```bash
./cbnt-prov read-config ./config.json ./firmware.rom
```

III Export KM, BPM and ACM from CBnT enabled firmware image
------------------------------------------------
1. Export of KM
```bash
./cbnt-prov export-km ./firmware.rom ./KM/km_export.bin
```

2. Export BPM
```bash
./cbnt-prov export-km ./firmware.rom ./BPM/bpm_export.bin
```

3. Export ACM
```bash
./cbnt-prov export-acm ./firmware.rom ./ACM/acm_export.bin
```

IV. Show details of exported KM, BPM, ACM
--------------------------------------
1. Show details of KM
```bash
./cbnt-prov show-km ./KM/km_signed.bin
```

2. Show details of BPM
```bash
./cbnt-prov show-bpm ./BPM/bpm_signed.bin
```

3. Show details of ACM
```bash
./cbnt-prov show-acm ./ACM/acm_signed.bin
```

4. Show all 
```bash
./cbnt-prov show-all ./firmware.rom
```