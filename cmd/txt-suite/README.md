Intel TXT Validation Test Suite
===============================

This Golang utility tests whether the platform supports Intel TXT and FIT, TPM
boot chain has been configured correctly under x86_64 linux.
The only supported architecture is x86_64.

[![GitHub Releases](https://img.shields.io/github/downloads/9elements/converged-security-suite/v2.0/total?label=Download%20v2.0&style=for-the-badge)](https://github.com/9elements/converged-security-suite/releases/latest/download/txt-suite)

Prerequisites for Usage
-----------------------
Supported OS: Any Linux distribution

Hardware Config: Provisionend Trusted Platform Module, JTAG disabled

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

**3. Check TPM driver is running and TSS is disabled.**

If /dev/tpm0 doesn't exist, load the *TPM* kernel module:
```bash
modprobe tpm_tis
```

Stop the *tpm2-abrmd.service* if running:
```bash
systemctl stop tpm2-abrmd.service
```

**4. Execute the txt-suite.**

```bash
sudo chmod +x txt-suite && sudo ./txt-suite
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
<GO111MODULE=on> go build -o txt-suite cmd/txt-suite/*.go
```

Create a configuration file:

**TPM** option
Can have the value *1.2* or *2.0*

**TXTMode** option (deprecated on CBnT)
Can have the value *auto* for autopromotion or *signed* for signed policy mode

**LCP2Hash** option (deprecated on CBnT)
Can have the values (*SHA1*, *SHA256*, *SHA384*, *SM3*, *NULL*) as the LCP2 hash

**platform.config**
```json
{
	"TPM": "2.0",
	"TXTMode": "auto",
	"LCP2Hash": "SHA256"
}
```

Run it as root:

```bash
./txt-suite -config platform.config
```

Commandline arguments
```bash
Usage of ./txt-suite:
  -all
        Run all the tests of the suite
  -cbnt
        Run CBnT specific tests
  -config string
        Give a path/filename to configuration file
  -i    Interactive mode. Errors will stop the testing.
  -l    Lists all test
  -log string
        Give a path/filename for test result output in JSON format. e.g.: /path/to/filename.json
  -m    Output test implementation state as Markdown
  -t string
        Select test number 1 - 50. e.g.: -t=1,2,3,4,...
  -tboot
        Test if tboot hypervisor runs correctly
  -tpm string
        Select TPM-Path. e.g.: -tpm=/dev/tpmX, with X as number of the TPM module
  -txtready
        Run TXTReady specific tests
  -uefi
        Test if platform is UEFI boot enabled
  -v    Shows Version, copyright info and license
```

API Usage
---------

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

**To test for TXTReady**:

```
package main

import (
	"log"

	"github.com/9elements/converged-security-suite/v2/pkg/hwapi"
	"github.com/9elements/converged-security-suite/v2/pkg/test"
)

func main() {
	hwAPI := hwapi.GetAPI()

	success, failureMsg, err := test.RunTestsSilent(hwAPI, nil, test.TestsTXTReady)
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

	"github.com/9elements/converged-security-suite/v2/pkg/hwapi"
	"github.com/9elements/converged-security-suite/v2/pkg/test"
)

func main() {
	hwAPI := hwapi.GetAPI()
	var config tools.Configuration
	config.LCPHash = tools.LCPPol2HAlgSHA256
	config.TPM = tss.TPMVersion20
	config.TXTMode = tools.AutoPromotion

	success, failureMsg, err := test.RunTestsSilent(hwAPI, &config, test.TestsTXTLegacyBoot)
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

Please take a look at the [TESTPLAN](TESTPLAN.md).
