Intel TXT Validation Test Suite
===============================

This Golang utility tests whether the platform supports Intel TXT and FIT, TPM
boot chain has been configured correctly.

The suite is work in progress.

Build Status
-----------
[![CircleCI](https://circleci.com/gh/9elements/txt-suite.svg?style=svg)](https://circleci.com/gh/9elements/txt-suite)

Usage
-----

The test suite runs on GNU/Linux. The `/dev/mem` device must allow access to the
full physical memory. You may have to add the following to the kernel command line:

```bash
iomem=relaxed strict-devmem=0 mem.devmem=1
```

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

There are currently no dependencies required.

To build the test suite run:

```bash
go build -o txt-suite cmd/txt-suite/*.go
```

Run it as root:

```bash
./txt-suite
```

Commandline arguments
```bash
-l : Lists all tests
-log : Specify a path/filename.json where test results will be written (only in combination with test enforcing (-i option))
-i : Enforces testing, so they won't stop at the first error. Test results will be written to test_log.json
-t=<n,m,o> : Choose tests, seperated by comma
-t=<n-m> or -t=<n-m,o-p> : Choose ranges of tests, can be seperated by comma
-v : Gives information about Licence, Copyright and Version
-h : Shows this information
```

Tests
-----

The test suite implements the following tests.

|  # | Test                                             | Implementation status  |
| -- | ------------------------------------------------ | ---------------------- |
| 00 | Intel CPU                                        | :white_check_mark:     |
| 01 | Weybridge or later                               | :white_check_mark:     |
| 02 | CPU supports TXT                                 | :white_check_mark:     |
| 03 | Chipset supports TXT                             | :x:                    |
| 04 | TXT register space accessible                    | :white_check_mark:     |
| 05 | CPU supports SMX                                 | :white_check_mark:     |
| 06 | CPU supports VMX                                 | :white_check_mark:     |
| 07 | IA32_FEATURE_CONTROL                             | :white_check_mark:     |
| 08 | GETSEC leaves are enabled                        | :x:                    |
| 09 | TXT not disabled by BIOS                         | :white_check_mark:     |
| 10 | BIOS ACM has run                                 | :white_check_mark:     |
| 11 | IBB is trusted                                   | :white_check_mark:     |
| 12 | TXT registers are locked                         | :white_check_mark:     |
| 13 | TPM connection                                   | :white_check_mark:     |
| 14 | TPM 1.2 present                                  | :white_check_mark:     |
| 15 | TPM 2 is present                                 | :white_check_mark:     |
| 16 | TPM is present                                   | :white_check_mark:     |
| 17 | TPM in production mode                           | :clock1:               |
| 18 | PS index set in NVRAM                            | :white_check_mark:     |
| 19 | AUX index set in NVRAM                           | :white_check_mark:     |
| 20 | PS index has valid LCP Policy                    | :white_check_mark:     |
| 21 | Valid FIT vector                                 | :white_check_mark:     |
| 22 | Valid FIT                                        | :white_check_mark:     |
| 23 | BIOS ACM entry in FIT                            | :white_check_mark:     |
| 24 | IBB entry in FIT                                 | :white_check_mark:     |
| 25 | LCP Policy entry in FIT                          | :white_check_mark:     |
| 26 | IBB covers reset vector                          | :white_check_mark:     |
| 27 | IBB covers FIT vector                            | :white_check_mark:     |
| 28 | IBB covers FIT                                   | :white_check_mark:     |
| 29 | IBB does not overlap                             | :white_check_mark:     |
| 30 | BIOS ACM does not overlap                        | :white_check_mark:     |
| 31 | IBB and BIOS ACM below 4GiB                      | :white_check_mark:     |
| 32 | TXT not disabled by LCP Policy                   | :white_check_mark:     |
| 33 | BIOSACM header valid                             | :white_check_mark:     |
| 34 | BIOSACM size check                               | :white_check_mark:     |
| 35 | BIOSACM alignment check                          | :white_check_mark:     |
| 36 | BIOSACM matches chipset                          | :white_check_mark:     |
| 37 | BIOSACM matches processor                        | :white_check_mark:     |
| 38 | TXT memory ranges valid                          | :white_check_mark:     |
| 39 | TXT memory reserved in e820                      | :white_check_mark:     |
| 40 | TXT memory in a DMA protected range              | :white_check_mark:     |
| 41 | TXT DPR register locked                          | :white_check_mark:     |
| 42 | CPU DMA protected range equals hostbridge DPR    | :white_check_mark:     |
| 43 | CPU hostbridge DPR register locked               | :white_check_mark:     |
| 44 | TXT region contains SINIT ACM                    | :white_check_mark:     |
| 45 | SINIT ACM matches chipset                        | :white_check_mark:     |
| 46 | SINIT ACM matches CPU                            | :white_check_mark:     |
| 47 | SINIT ACM startup successful                     | :white_check_mark:     |
| 48 | BIOS DATA REGION present                         | :white_check_mark:     |
| 49 | BIOS DATA REGION valid                           | :white_check_mark:     |
| 50 | BIOS DATA NumLogProcs valid                      | :white_check_mark:     |
| 51 | CPU supports memory type range registers         | :white_check_mark:     |
| 52 | CPU supports system management range registers   | :white_check_mark:     |
| 53 | SMRR covers SMM memory                           | :white_check_mark:     |
| 54 | SMRR protection active                           | :white_check_mark:     |
| 55 | IOMMU/VT-d active                                | :white_check_mark:     |
| 56 | TBOOT hypervisor active                          | :x:                    |
| 57 | TXT server mode enabled                          | :white_check_mark:     |
| 58 | FSB interface release fused                      | :x:                    |
