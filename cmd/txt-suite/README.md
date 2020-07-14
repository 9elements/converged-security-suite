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
CONFIG_X86_MSR=y
CONFIG_INTEL_IOMMU=y
CONFIG_INTEL_IOMMU_DEFAULT_ON=y
```

**To test for TXTReady**:

```
package main

import (
	"log"

	"github.com/9elements/converged-security-suite/pkg/hwapi"
	"github.com/9elements/converged-security-suite/pkg/test"
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

	"github.com/9elements/converged-security-suite/pkg/hwapi"
	"github.com/9elements/converged-security-suite/pkg/test"
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

Please take a look at the [TESTPLAN](TESTPLAN.md).
