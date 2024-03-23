Intel TXT Provisioning
===============================

This Golang utility provisions the Trusted Platform Module on a Intel TXT capable machine.

Prerequisites for Usage
-----------------------
Supported OS: Any Linux distribution

Hardware Config: Unprovisionend Trusted Platform Module

How to Compile
--------------

Get Golang >=1.11 and export:
```
export GO111MODULE=on
```
or set it in front of every go command.
This environment variable activates modules for GO 1.11


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
<GO111MODULE=on> go build -o txt-prov cmd/txt-prov/*.go
```

Create a configuration file:

Please get necessary information out of the Intel TXT documents/provisioning tools.

**lcp.json**
```json
{
    "Version": "0x300",
    "HashAlg": "SHA256",
    "PolicyType": "Any",
    "SINITMinVersion":"0",
    "MaxSINITMinVersion": "ff",
    "PolicyControl":"",
    "LcpHashAlgMask":"SHA256",
    "LcpSignAlgMask": "RSA2048SHA256"
}
```

Run it as root:

```bash
./txt-prov -config lcp.json -prov
```

Commandline subcommands
--------------
```bash
Usage of ./txt-prov:
  aux-define
      Define AUX index if not exists in TPM NVRAM
  aux-delete
      Delete AUX index if exists in TPM NVRAM
  ps-define
      Define PS index if not exists in TPM NVRAM
  ps-delete
      Delete PS index if exists in TPM NVRAM
  platform-prov
      Provision PS & AUX index with LCP config
  ps-update
      Update PS index content in TPM NVRAM
  show
      Shows current provisioned PS & AUX index in NVRAM on stdout
  version    
      Shows version and license information
```
Further information are available via:
```bash
./txt-prov <subcommand> -h
```

Showing the NVRAM indices and LCP policy
```bash
NV index overview

PS NV index
   Index: 0x1c10103
   Attributes: PlatformCreate + PolicyWrite + PolicyDelete + AuthRead + No Do + Writte
   Size: 70
   AuthPolicy: 0x85b1cdcf3bb7205b0c9375f68f448b76411d3091199ced7fca5093ec76a2b6bd

AUX NV index
   Index: 0x1c10102
   Attributes: No Do + AuthRead + Writte + WriteSTClear + PlatformCreate + PolicyWrite + PolicyDelete
   Size: 104
   AuthPolicy: 0xef9a26fc22d1ae8cecff59e9481ac1ec533dbe228bec6d17930f4cb2cc5b9724

PS index LCP Policy
   Version: 0x300
   HashAlg: SHA256
   PolicyType: Any
   SINITMinVersion: 0
   DataRevocationCounters:
   PolicyControl:
   MaxSINITMinVersion: ff
   LcpHashAlgMask: SHA256
   LcpSignAlgMask: RSA2048SHA256
   PolicyHash: [0 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 19 20 21 22 23 24 25 26 27 28 29 30 31]
```
