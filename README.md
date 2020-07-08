Intel TXT Validation Test Suite
===============================

This Golang utility tests whether the platform supports Intel TXT and FIT, TPM
boot chain has been configured correctly under x86_64 linux.
The only supported architecture is x86_64.

The suite is work in progress.

Build Status
-----------
[![CircleCI](https://circleci.com/gh/9elements/txt-suite.svg?style=svg)](https://circleci.com/gh/9elements/txt-suite)


Using Go Modules => needs GO Version >= 1.11

Usage
-----

The test suite runs on GNU/Linux and needs access to physical memory. Nowadays
most GNU/Linux distributions limit of forbid that. If you get an error on the
lines of "cannot read from /dev/mem: operation not permitted" you may have to
add the following to the kernel command line:

```bash
iomem=relaxed strict-devmem=0 mem.devmem=1 intel_iommu=on
```

If that does not help get, compile and load the
[`fmem`](https://github.com/9elements/fmem) kernel module.

Prepare the environment:

Load the *msr* kernel module:
```bash
modprobe msr
```

If /dev/tpm0 doesn't exist, load the *TPM* kernel module:
```bash
modprobe tpm_tis
```

Stop the *tpm2-abrmd.service* if running:
```bash
systemctl stop tpm2-abrmd.service
```

For GO 1.11 you need to:
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
<GO111MODULE=on> go build -o txt-suite cmd/txt-suite/*.go
```

Run it as root:

```bash
./txt-suite
```

Commandline arguments
```bash
-m : Generate markdown
-l : Lists all tests
-log : Specify a path/filename.json where test results will be written (only in combination with test enforcing (-i option))
-i : interactive move - Test will stop if an error occurs. Test results will be written to test_log.json
-t=<n,m,o> : Choose tests, seperated by comma
-t=<n-m> or -t=<n-m,o-p> : Choose ranges of tests, can be seperated by comma
-v : Gives information about Licence, Copyright and Version
-h : Shows this information
-txtready   : Test if platform is TXTReady
-legacyboot : Test if platform is TXT Legacy boot enabled
```

API Usage
---------

**Requirements for the Kernel configuration**

```
CONFIG_DEVMEM=y
CONFIG_STRICT_DEVMEM=n
CONFIG_TCG_TIS=y
CONFIG_TCG_CRB=y
```

**To test for TXTReady**:

```
package main

import (
	"log"

	"github.com/9elements/txt-suite/pkg/hwapi"
	"github.com/9elements/txt-suite/pkg/test"
)

func main() {
	hwAPI := hwapi.GetAPI()

	success, failureMsg, err := test.RunTestsSilent(hwAPI, test.TestsTXTReady)
	if err != nil {
		log.Fatal(err)
	}
	if !success {
		log.Printf("Platform not TXTReady as of: '%s'\n", failureMsg)
	} else {
		log.Printf("Platform is TXTReady!\n")
	}
}
```


**To test for TXT legacy boot (Initial Bootblock measured before PoR)**:

```
package main

import (
	"log"

	"github.com/9elements/txt-suite/pkg/hwapi"
	"github.com/9elements/txt-suite/pkg/test"
)

func main() {
	hwAPI := hwapi.GetAPI()

	success, failureMsg, err := test.RunTestsSilent(hwAPI, test.TestsTXTLegacyBoot)
	if err != nil {
		log.Fatal(err)
	}
	if !success {
		log.Printf("Platform not TXTReady as of: '%s'\n", failureMsg)
	} else {
		log.Printf("Platform is TXTReady!\n")
	}
}
```

Tests
-----

The test suite implements the following tests.

|  # | Test                                             | Implementation status  |
| -- | ------------------------------------------------ | ---------------------- |
| 00 | Intel CPU                                        | :white_check_mark:     |
| 01 | Weybridge or later                               | :white_check_mark:     |
| 02 | CPU supports TXT                                 | :white_check_mark:     |
| 03 | TXT register space accessible                    | :white_check_mark:     |
| 04 | CPU supports SMX                                 | :white_check_mark:     |
| 05 | CPU supports VMX                                 | :white_check_mark:     |
| 06 | IA32_FEATURE_CONTROL                             | :white_check_mark:     |
| 07 | TXT not disabled by BIOS                         | :white_check_mark:     |
| 08 | BIOS ACM has run                                 | :white_check_mark:     |
| 09 | IBB is trusted                                   | :white_check_mark:     |
| 10 | TXT registers are locked                         | :white_check_mark:     |
| 11 | IA32 debug interface isn't disabled              | :white_check_mark:     |
| 12 | TPM connection                                   | :white_check_mark:     |
| 13 | TPM 1.2 present                                  | :white_check_mark:     |
| 14 | TPM 2 is present                                 | :white_check_mark:     |
| 15 | TPM is present                                   | :white_check_mark:     |
| 16 | TPM NVRAM is locked                              | :white_check_mark:     |
| 17 | PS Index has correct config                      | :white_check_mark:     |
| 18 | AUX Index has correct config                     | :white_check_mark:     |
| 19 | PO Index has correct config                      | :white_check_mark:     |
| 20 | PS index has valid LCP Policy                    | :white_check_mark:     |
| 21 | PO index has valid LCP Policy                    | :white_check_mark:     |
| 22 | PCR 0 is set correctly                           | :white_check_mark:     |
| 23 | Valid FIT vector                                 | :white_check_mark:     |
| 24 | Valid FIT                                        | :white_check_mark:     |
| 25 | BIOS ACM entry in FIT                            | :white_check_mark:     |
| 26 | IBB entry in FIT                                 | :white_check_mark:     |
| 27 | LCP Policy entry in FIT                          | :white_check_mark:     |
| 28 | IBB covers reset vector                          | :white_check_mark:     |
| 29 | IBB covers FIT vector                            | :white_check_mark:     |
| 30 | IBB covers FIT                                   | :white_check_mark:     |
| 31 | IBB does not overlap                             | :white_check_mark:     |
| 32 | BIOS ACM does not overlap                        | :white_check_mark:     |
| 33 | IBB and BIOS ACM below 4GiB                      | :white_check_mark:     |
| 34 | TXT not disabled by LCP Policy                   | :white_check_mark:     |
| 35 | BIOSACM header valid                             | :white_check_mark:     |
| 36 | BIOSACM size check                               | :white_check_mark:     |
| 37 | BIOSACM alignment check                          | :white_check_mark:     |
| 38 | BIOSACM matches chipset                          | :white_check_mark:     |
| 39 | BIOSACM matches processor                        | :white_check_mark:     |
| 40 | TXT memory ranges valid                          | :white_check_mark:     |
| 41 | TXT memory reserved in e820                      | :white_check_mark:     |
| 42 | TXT memory in a DMA protected range              | :white_check_mark:     |
| 43 | TXT DPR register locked                          | :white_check_mark:     |
| 44 | CPU DPR equals hostbridge DPR                    | :white_check_mark:     |
| 45 | CPU hostbridge DPR register locked               | :white_check_mark:     |
| 46 | TXT region contains SINIT ACM                    | :white_check_mark:     |
| 47 | SINIT ACM matches chipset                        | :white_check_mark:     |
| 48 | SINIT ACM matches CPU                            | :white_check_mark:     |
| 49 | SINIT ACM startup successful                     | :white_check_mark:     |
| 50 | BIOS DATA REGION present                         | :white_check_mark:     |
| 51 | BIOS DATA REGION valid                           | :white_check_mark:     |
| 52 | CPU supports MTRRs                               | :white_check_mark:     |
| 53 | CPU supports SMRRs                               | :white_check_mark:     |
| 54 | SMRR covers SMM memory                           | :white_check_mark:     |
| 55 | SMRR protection active                           | :white_check_mark:     |
| 56 | IOMMU/VT-d active                                | :white_check_mark:     |
| 57 | TXT server mode enabled                          | :white_check_mark:     |
