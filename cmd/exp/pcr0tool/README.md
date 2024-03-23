# `pcr0tool`

This is a swiss tool to do any PCR0 related operations. PCR0 is the TPM
register used for firmware measurements.

[![GitHub Releases](https://img.shields.io/github/downloads/9elements/converged-security-suite/v2.0/total?label=Download%20v2.0&style=for-the-badge)](https://github.com/9elements/converged-security-suite/releases/latest/download/txt-suite)

## Prerequisites

**Supported OS: Any Linux distribution**

**Hardware Config: no requirements**

**Requirements for the Kernel configuration**

```
CONFIG_DEVMEM=y
CONFIG_STRICT_DEVMEM=n
CONFIG_TCG_TIS=y
CONFIG_TCG_CRB=y
CONFIG_X86_MSR=y
CONFIG_INTEL_IOMMU=y
CONFIG_INTEL_IOMMU_DEFAULT_ON=y
```

**1. Get the kernel command-line right and enable relaxed memory access on /dev/mem and IOMMU.**

Add this line to your kernel configuration and then reboot.

```bash
iomem=relaxed intel_iommu=on
```

If that does not work get, compile and load the
[`fmem`](https://github.com/9elements/fmem) kernel module.

**2. Load the MSR kernel module.**

Load the *msr* kernel module:
```bash
modprobe msr
```

**3. Execute the pcr0tool.**

```bash
sudo chmod +x pcr0tool && sudo ./pcr0tool
```

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
<GO111MODULE=on> go build -o pcr0tool cmd/pcr0tool/
```

## Functions

* `sum` -- Performs offline calculation of a PCR0 value for a specific firmware image.
* `diff` -- Explains the reason of the difference in PCR0 values between two firmware images. Useful to diagnose dumped images.
* `dump_fit` -- Prints FIT as JSON.
* `dump_registers` -- Prints related registers from `/dev/mem` and `/dev/cpu/0/msr`.
* `printnodes` -- Prints the layout of a firmware image.

### `sum`

```
$ pcr0tool sum --help
syntax: pcr0tool sum [options] <firmware>

Options:
  -flow string
    	values: 'Auto', 'LegacyTXTDisabled', 'LegacyTXTEnabled', 'LegacyTXTEnabledTPM12', 'CBnT0T' (default "Auto")
  -hash-func string
    	which hash function use to hash measurements and to extend the PCR0; values: "sha1", "sha256" (default "sha1")
  -quiet
    	display only the result
  -registers string
    	[optional] file that contains registers as a json array (use value '/dev' to use registers of the local machine)
```

`pcr0tool sum` performs an offline calculation of a PCR0 value for a specific firmware image.
It supported measurement flows:
* [Intel] CBnT 0T with TPM2.0.
* [Intel] Legacy (pre-CBnT) TXT-enabled with TPM2.0.
* [Intel] Legacy (pre-CBnT) TXT-enabled with TPM1.2.
* [Intel] Legacy (pre-CBnT) TXT-disabled.

An example:
```
$ pcr0tool sum /tmp/firmware.fd | tail -1
Resulting PCR0: 730113CEF5D90744CF3B5AF67C8977EB265FB3D1
```
(where `/tmp/firmware.fd` is a path to a firmware image)

CBnT flows depends on status registers, which are not deterministic from the
firmware itself and also ACM_POLICY_STATUS register value should be supplied
through option `-registers`. If the tool is executed on a machine with the
same state as the one expected one then it is possible to just use option
`-registers /dev`, for example:
```
$ sudo pcr0tool sum -registers /dev /tmp/firmware.fd | tail -1
Resulting PCR0: C38B75342316F27731614015FF83F695A6F2C28F
```
(we prepended with `sudo` since `/dev/mem` and `/dev/cpu/0/msr` usually requires
root privileges)

But if the calculation is performed on another machine then it is required
to dump registers of the expected state (from the target machine) with:
```
$ pcr0tool dump_registers -output /tmp/registers.json
```
Copy `registers.json` to the calculating host and execute there:
```
$ sudo pcr0tool sum -registers /tmp/registers.json /tmp/firmware.fd | tail -1
Resulting PCR0: C38B75342316F27731614015FF83F695A6F2C28F
```

Keep in mind, auto-detection of legacy TXT-enabled is not working properly right
now (likely a bug in the tool), therefore we recommend to explicitly set
the flow is this is the case:
```
$ pcr0tool sum -flow LegacyTXTEnabled /tmp/firmware.fd | tail -1
Resulting PCR0: 7828463C0A3CC9CF69046D2D5F0714AAB896AA7C
```

### `diff`

```
$ pcr0tool diff --help
syntax: pcr0tool diff [options] <firmware_good> <firmware_bad>

Options:
  -deep-analysis
    	Also perform slow procedures to find more byte ranges which could affect the PCR0 calculation. This is experimental feature! Values: "true", "false"
  -flow string
    	values: 'Auto', 'LegacyTXTDisabled', 'LegacyTXTEnabled', 'LegacyTXTEnabledTPM12', 'CBnT0T' (default "auto")
  -force-scan-area string
    	Force the scan area instead of following the PCR0 calculation. Values: "" (follow the PCR0 calculation), "bios_region"
  -hash-func string
    	which hash function use to hash measurements and to extend the PCR0; values: "sha1", "sha256"
  -ignore-byte-set string
    	Define a set of bytes to ignore while the comparison.
    	It makes sense to use this option together with "-force-scan-area bios_region" to scan the whole image,
    	but ignore the overridden bytes. The value is represented in hex characters separated by comma, for example: "00,ff". Default: ""
  -net-pprof string
    	start listening for "net/http/pprof", example value: "127.0.0.1:6060"
  -output-format string
    	Values: "analyzed-text", "analyzed-json", "json" (default "analyzed-text")
  -registers string
    	[optional] file that contains registers as a json array (use value '/dev' to use registers of the local machine)
```

`diff` compares two firmware images in terms of their PCR0 values and explains
what contributes into difference.

Options `-flow`, `-hash-func` and `-registers` has the same meaning as in `sum`.

An example:
```
$ pcr0tool diff -flow LegacyTXTEnabled /tmp/firmware.fd /tmp/firmware.fd-hacked
debugInfo: {
  "config_orig": {
    "Flow": 2,
    "FindMissingFakeMeasurements": false,
    "Registers": [],
    "PCR0DataIbbDigestHashAlgorithm": 0
  },
  "config_result": {
    "Flow": 2,
    "FindMissingFakeMeasurements": false,
    "Registers": [],
    "PCR0DataIbbDigestHashAlgorithm": 0
  },
  "detectedAttestationFlow": "LegacyTXTDisabled",
  "errorFlowDetection": null,
  "scanRanges": [
    {
      "Offset": 29098004,
      "Length": 4
    },
    {
      "Offset": 29032800,
      "Length": 48
    },
    {
      "Offset": 29360128,
      "Length": 4194304
    },
    {
      "Offset": 31025984,
      "Length": 43006
    },
    {
      "Offset": 17956864,
      "Length": 11071488
    },
    {
      "Offset": 33554368,
      "Length": 16
    },
    {
      "Offset": 29032448,
      "Length": 448
    }
  ],
  "warnings": "errors: unable to collect measurement 'pcdFirmwareVendor_measured_data': unable to find the source of firmware vendor version"
}
{"ID":"init","Data":[{"Range":{"Offset":0,"Length":0}}]}
{"ID":"ACM_date","Data":[{"Range":{"Offset":29098004,"Length":4}}]}
{"ID":"BIOS_startup_module","Data":[{"ID":"BIOS_startup_module_0","Range":{"Offset":29032800,"Length":48}},{"ID":"BIOS_startup_module_1","Range":{"Offset":29360128,"Length":4194304}}]}
{"ID":"S-CRTM_separator","Data":[{"Range":{"Offset":0,"Length":0},"ForceData":"AAAAAA=="}]}
{"ID":"pcdFirmwareVendor_measured_data","Data":[{"Range":{"Offset":0,"Length":0},"ForceData":"HvtrVAwdVUCkrU70vxe4Og=="}]}
{"ID":"pcdFirmwareVendor_code","Data":[{"Range":{"Offset":31025984,"Length":43006}}]}
{"ID":"DXE","Data":[{"Range":{"Offset":17956864,"Length":11071488}}]}
{"ID":"separator","Data":[{"Range":{"Offset":0,"Length":0},"ForceData":"AAAAAA=="}]}
{"ID":"FIT_pointer","Data":[{"Range":{"Offset":33554368,"Length":16}}]}
{"ID":"FIT_headers","Data":[{"Range":{"Offset":29032448,"Length":448}}]}

offset: 0x11205da; bytes differs: 1; hamming distance is: 2, for non-(0x00|0xff): 2.
related measurements: DXE
related nodes: [bios_region volume:5C60F367-A505-419A-859E-2A4FF6CA6FE5 file:AB7ED12E-1D78-4635-AB87-23F00A911EC7]
0x00000000011205D0:   42    25    7A    8F    95    F8    8B    A6
0x00000000011205D8:   D2    F0    0D|3D 12    FE    36    76    63
0x00000000011205E0:   49    C9    9C    2A    6A    3C    FF    C0

offset: 0x1bc0015; bytes differs: 1; hamming distance is: 1, for non-(0x00|0xff): 1.
related measurements: ACM_date
related nodes: [bios_region]
0x0000000001BC0008:   00    00    00    00    07    B0    00    00
0x0000000001BC0010:   86    80    00    00    06    03|07 18    20
0x0000000001BC0018:   00    00    01    00    02    00    00    00

offset: 0x1d96b91; bytes differs: 1; hamming distance is: 2, for non-(0x00|0xff): 2.
related measurements: BIOS_startup_module:BIOS_startup_module_1, pcdFirmwareVendor_code
related nodes: [bios_region volume:61C0F511-A691-4F54-974F-B9A42172CE53 file:9B3F28D5-10A6-46C8-BA72-BD40B847A71A:AmiTcgPlatformPeiAfterMem]
0x0000000001D96B88:   F3    36    35    3F    F3    23    F1    03
0x0000000001D96B90:   03    08|10 00    00    64    A7    00    10
0x0000000001D96B98:   4D    5A    00    00    00    00    00    00

offset: 0x1d97a57; bytes differs: 1; hamming distance is: 4, for non-(0x00|0xff): 0.
related measurements: BIOS_startup_module:BIOS_startup_module_1, pcdFirmwareVendor_code
related nodes: [bios_region volume:61C0F511-A691-4F54-974F-B9A42172CE53 file:9B3F28D5-10A6-46C8-BA72-BD40B847A71A:AmiTcgPlatformPeiAfterMem]
0x0000000001D97A48:   6A    00    B8    0C    1D    00    00    66
0x0000000001D97A50:   89    44    24    14    6A    00    B8    55|FF
0x0000000001D97A58:   40    00    00    66    89    44    24    1A

offset: 0x1ffffc2; bytes differs: 1; hamming distance is: 3, for non-(0x00|0xff): 3.
related measurements: BIOS_startup_module:BIOS_startup_module_1, FIT_pointer
related nodes: [bios_region volume:61C0F511-A691-4F54-974F-B9A42172CE53 file:1BA0062E-C779-4582-8566-336AE8F78F09]
0x0000000001FFFFB8:   00    00    00    00    44    00    00    19
0x0000000001FFFFC0:   00    00    BB|BC FF    00    00    00    00
0x0000000001FFFFC8:   00    00    00    00    00    00    00    00

Total:
	changed bytes: 5 (in 5 ranges)
	hamming distance: 12
	hamming distance for non-(0x00|0xff) bytes: 8
The earliest offset of a different measured bytes: 0x11205da
```

Here we see that the PCR0 value of two images are not the same because of 
difference in: FIT pointer, AmiTcgPlatformPeiAfterMem, AmiTcgPlatformPeiAfterMem,
ACM date and file "AB7ED12E-1D78-4635-AB87-23F00A911EC7".

This is not the same as:
```
diff <(xxd /tmp/firmware.fd) <(xxd /tmp/firmware.fd-hacked)
```
because `/tmp/firmware.fd-hacked` might have a lot of data modified outside
measured areas. For example if the firmware flashed and then dumped it will
usually differ a lot from the original image.

If you want to enforce checking of the whole BIOS region (which is not
the same as the whole firmware image) then you may use option
`-force-scan-area bios_region`. But in this case it likely will produce a lot
of garbage output while comparison a dumped firmware with the original one,
because placeholders will be replaced with some values. To avoid this problem
you may use option `-ignore-byte-set 00,ff` -- it will ignore difference in
bytes which were overridden from/to values `0x00` and `0xFF` (these values
are usually used as placeholders).

Option `-deep-analysis` is a desperate (last resort) tool to find an explanation
of difference PCR0 values. It also tries to find metadata which might affect
parsing of the image (and check for difference in there). Expected to be used only
for debugging purposes.

### `dump_fit`

`dump_fit` just dumps FIT of a firmware image as JSON. The output format
is not stable, yet.

An example:
```
$ pcr0tool dump_fit /tmp/firmware.fd | jq '.[] | select(.Headers.TypeAndIsChecksumValid.type == 2) | .DataParsed.EntrySACMDataInterface.ChipsetID'
45063
```

### `dump_registers`

`dump_registers` reads status registers from the local machine and prints them.

An example:
```
$ pcr0tool dump_registers

Register: ACM_POLICY_STATUS
                    6         5         4         3         2         1         0
                 3210987654321098765432109876543210987654321098765432109876543210
0000000200108496 0000000000000000000000000000001000000000000100001000010010010110
	 0- 3:        6: Key Manifest ID
	 4- 4:        1: BP.TYPE.M – BtG measures IBB into the TPM
	 5- 5:        0: BP.TYPE.V – BtG verifies IBB
	 6- 6:        0: BP.TYPE.HAP – Indicates HAP platform
	 7- 7:        1: BP.TYPE.T – Indicates TXT supported
	 8- 8:        0: <reserved>
	 9- 9:        0: BP.RSTR.DCD – Disable CPU debug
	10-10:        1: BP.RSTR.DBI – Disable BSP init
	11-11:        0: BP.RSTR.PBE Protect BIOS environment
	12-12:        0: <reserved>
	13-14:        0: TPM type
	15-15:        1: TPM Success
	16-18:        0: <reserved>
	19-19:        0: Backup action
	20-24:        1: TXT profile selection
	25-26:        0: Memory scrubbing Policy
	27-28:        0: <reserved>
	29-29:        0: IBB DMA Protection
	30-31:        0: <reserved>
	32-34:        2: S-CRTM Status
	35-35:        0: CPU Co-signing Enabled
	36-36:        0: TPM Startup locality
	37-63:        0: <reserved>

Register: ACM_STATUS
                    6         5         4         3         2         1         0
                 3210987654321098765432109876543210987654321098765432109876543210
0000000000830000 0000000000000000000000000000000000000000100000110000000000000000
	 0- 3:        0: Module Type
	 4- 9:        0: Class Code
	10-14:        0: Major Error Code
	15-15:        0: ACM_Started
	16-27:       83: Minor Error Code
	28-30:        0: <reserved>
	31-63:        0: Valid

Register: TXT.DPR
          3         2         1         0
         10987654321098765432109876543210
70000081 01110000000000000000000010000001
	 0- 0:        1: Lock
	 1- 3:        0: <reserved>
	 4-11:        8: Size of memory, in MB, that will be protected from DMA access
	12-19:        0: <reserved>
	20-31:      700: Top address + 1 of DPR. This is the base of TSEG

Register: TXT.ERRORCODE
          3         2         1         0
         10987654321098765432109876543210
00000000 00000000000000000000000000000000
	 0- 3:        0: Module Type
	 4- 9:        0: Class Code
	10-14:        0: Major Error Code
	15-15:        0: Software Source
	16-27:        0: Type1/Minor Error Code
	28-29:        0: Type1/<reserved> Provides implementation and source specific details on the failure condition
	30-30:        0: Processor (0) /Software (1)
	31-31:        0: Valid

Register: TXT.PUBLIC.KEY

9C 78 F0 D8 53 DE 85 4A
2F 47 76 1C 72 B8 6A 11
16 4A 66 A9 84 C1 AA D7
92 E3 14 4F B7 1C 2D 11
	 0-255: 9C78F0D853DE854A2F47761C72B86A11164A66A984C1AAD792E3144FB71C2D11: Hash of the public key used for verification of AC modules

Register: TXT.STS
                    6         5         4         3         2         1         0
                 3210987654321098765432109876543210987654321098765432109876543210
0000000000004092 0000000000000000000000000000000000000000000000000100000010010010
	 0- 0:        0: SENTER.DONE.STS
	 1- 1:        1: SEXIT.DONE.STS
	 2- 5:        4: <reserved>
	 6- 6:        0: MEM-CONFIGLOCK.STS
	 7- 7:        1: PRIVATEOPEN.STS
	 8-14:       40: <reserved>
	15-15:        0: TXT.LOCALITY1.OPEN.STS
	16-16:        0: TXT.LOCALITY2.OPEN.STS
	17-63:        0: <reserved>

Register: TXT.ESTS
          1         0
         109876543210
00000000 00000000
	 0- 0:        0: TXT_RESET.STS
	 1- 7:        0: <reserved>

Register: TXT.SPAD
                    6         5         4         3         2         1         0
                 3210987654321098765432109876543210987654321098765432109876543210
8D74000040402003 1000110101110100000000000000000001000000010000000010000000000011
	 0-29:   402003: <reserved>
	30-30:        1: TXT Startup success
	31-46:        0: Boot Status
	47-47:        0: Memory power down executed
	48-52:       14: Boot Status details
	53-53:        1: TXT Policy enable
	54-58:       15: Boot Status details
	59-59:        1: BIOS trusted
	60-60:        0: TXT Policy disable
	61-61:        0: Boot Status details
	62-62:        0: Indicates ACM authentication error
	63-63:        1: S-ACM success

Register: TXT.VER.FSBIF
          3         2         1         0
         10987654321098765432109876543210
FFFFFFFF 11111111111111111111111111111111
	 0-31: FFFFFFFF: <reserved>

Register: TXT.VER.EMIF
          3         2         1         0
         10987654321098765432109876543210
9D003000 10011101000000000011000000000000
	 0-31: 9D003000: <reserved>

Register: TXT.DIDVID
                    6         5         4         3         2         1         0
                 3210987654321098765432109876543210987654321098765432109876543210
00000001B0078086 0000000000000000000000000000000110110000000001111000000010000110
	 0-15:     8086: Vendor ID
	16-31:     B007: Device ID
	32-47:        1: Revision ID
	48-63:        0: Extended ID

Register: TXT.SINIT.BASE
          3         2         1         0
         10987654321098765432109876543210
6FEB0000 01101111111010110000000000000000
	 0-31: 6FEB0000: <reserved>

Register: TXT.SINIT.SIZE
          3         2         1         0
         10987654321098765432109876543210
00050000 00000000000001010000000000000000
	 0-31:    50000: <reserved>

Register: TXT.MLE.JOIN
          3         2         1         0
         10987654321098765432109876543210
00000000 00000000000000000000000000000000
	 0-31:        0: <reserved>

Register: TXT.HEAP.BASE
          3         2         1         0
         10987654321098765432109876543210
6FF00000 01101111111100000000000000000000
	 0-31: 6FF00000: <reserved>

Register: TXT.HEAP.SIZE
          3         2         1         0
         10987654321098765432109876543210
00100000 00000000000100000000000000000000
	 0-31:   100000: <reserved>

Register: BTG_SACM_INFO
                    6         5         4         3         2         1         0
                 3210987654321098765432109876543210987654321098765432109876543210
0000000D00000000 0000000000000000000000000000110100000000000000000000000000000000
	 0- 0:        0: NEMEnabled
	 1- 2:        0: TPMType
	 3- 3:        0: TPMSuccess
	 4- 4:        0: Force Anchor Boot
	 5- 5:        0: Measured
	 6- 6:        0: Verified
	 7- 7:        0: ModuleRevoked
	 8-31:        0: <reserved>
	32-32:        1: BootGuardCapability
	33-33:        0: <reserved>
	34-34:        1: ServerTXTCapability
	35-35:        1: No Reset Secrets Protection
	36-63:        0: <reserved>

Register: IA32_DEBUG_INTERFACE
                    6         5         4         3         2         1         0
                 3210987654321098765432109876543210987654321098765432109876543210
0000000040000000 0000000000000000000000000000000001000000000000000000000000000000
	 0- 0:        0: Enable
	 1-29:        0: <reserved>
	30-30:        1: Lock
	31-31:        0: DebugOccurred
	32-63:        0: <reserved>

Register: IA32_FEATURE_CONTROL
                    6         5         4         3         2         1         0
                 3210987654321098765432109876543210987654321098765432109876543210
000000000010FF07 0000000000000000000000000000000000000000000100001111111100000111
	 0- 0:        1: Lock (0 =unlocked, 1 = locked)
	 1- 1:        1: Enables VMXON in SMX operation
	 2- 2:        1: Enables VMXON outside of SMX operation
	 3- 7:        0: <reserved>
	 8-14:       7F: SENTER Enables
	15-15:        1: SENTER Global Enable
	16-63:       10: <reserved>

Register: IA32_MTRRCAP
                    6         5         4         3         2         1         0
                 3210987654321098765432109876543210987654321098765432109876543210
0000000000002D0A 0000000000000000000000000000000000000000000000000010110100001010
	 0- 7:        A: VCNT (Number of variable range registers)
	 8- 8:        1: FIX (Fixed range registers supported)
	 9- 9:        0: <reserved>
	10-10:        1: WC (Write-combining memory type supported)
	11-11:        1: SMRR interface supported
	12-63:        2: <reserved>

Register: IA32_PLATFORM_ID
                    6         5         4         3         2         1         0
                 3210987654321098765432109876543210987654321098765432109876543210
001C000000000000 0000000000011100000000000000000000000000000000000000000000000000
	 0-49:        0: <reserved>
	50-52:        7: Processor Flag
	53-63:        0: <reserved>

Register: IA32_SMRR_PHYSBASE
                    6         5         4         3         2         1         0
                 3210987654321098765432109876543210987654321098765432109876543210
0000000070000006 0000000000000000000000000000000001110000000000000000000000000110
	 0- 7:        6: Type
	 8-11:        0: <reserved>
	12-31:    70000: PhysBase
	32-63:        0: <reserved>

Register: IA32_SMRR_PHYSMASK
                    6         5         4         3         2         1         0
                 3210987654321098765432109876543210987654321098765432109876543210
00000000F8000800 0000000000000000000000000000000011111000000000000000100000000000
	 0-10:        0: <reserved>
	11-11:        1: V (Valid)
	12-31:    F8000: PhysMask
	32-63:        0: <reserved>
```

### `printnodes`

`printnodes` prints a firmware layout. An example:

```
$ pcr0tool printnodes /tmp/firmware.fd | head -15
0 ________-____-____-____-____________ *uefi.FlashImage  0 0
1 ________-____-____-____-____________ *uefi.FlashDescriptor  0 0
1 ________-____-____-____-____________ *uefi.RawRegion  0 0
1 ________-____-____-____-____________ *uefi.MERegion  0 0
2 ________-____-____-____-____________ *uefi.MEFPT  0 0
1 ________-____-____-____-____________ *uefi.RawRegion  0 0
1 ________-____-____-____-____________ *uefi.RawRegion  0 0
1 ________-____-____-____-____________ *uefi.RawRegion  0 0
1 ________-____-____-____-____________ *uefi.RawRegion  0 0
1 ________-____-____-____-____________ *uefi.RawRegion  0 0
1 ________-____-____-____-____________ *uefi.BIOSRegion  16777216 16777216
2 FA4974FC-AF1D-4E5D-BDC5-DACD6D27BAEC *uefi.FirmwareVolume  16777216 524288
3 CEF5B9A3-476D-497F-9FDC-E98143E0422C *uefi.File  16777336 524168
4 ________-____-____-____-____________ *uefi.NVarStore  0 0
5 ________-____-____-____-____________ *uefi.NVar  0 0
```

```
$ pcr0tool printnodes -as-tree /tmp/firmware.fd | head -15
________-____-____-____-____________ *uefi.FlashImage  0 0
  ________-____-____-____-____________ *uefi.FlashDescriptor  0 0
  ________-____-____-____-____________ *uefi.RawRegion  0 0
  ________-____-____-____-____________ *uefi.MERegion  0 0
    ________-____-____-____-____________ *uefi.MEFPT  0 0
  ________-____-____-____-____________ *uefi.RawRegion  0 0
  ________-____-____-____-____________ *uefi.RawRegion  0 0
  ________-____-____-____-____________ *uefi.RawRegion  0 0
  ________-____-____-____-____________ *uefi.RawRegion  0 0
  ________-____-____-____-____________ *uefi.RawRegion  0 0
  ________-____-____-____-____________ *uefi.BIOSRegion  16777216 16777216
    FA4974FC-AF1D-4E5D-BDC5-DACD6D27BAEC *uefi.FirmwareVolume  16777216 524288
      CEF5B9A3-476D-497F-9FDC-E98143E0422C *uefi.File  16777336 524168
        ________-____-____-____-____________ *uefi.NVarStore  0 0
          ________-____-____-____-____________ *uefi.NVar  0 0
```
Last two columns are: offset and length. If a value was not determined
(node type is not supported, yet) then a zero is printed.