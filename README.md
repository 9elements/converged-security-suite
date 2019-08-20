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

The only dependency is a working Go toolchain and the  `dep` tool. After cloning
the repository, fetch the dependencies:

```bash
dep ensure
```

Then, run the test suite as root.

```bash
go run cmd/txt-suite/main.go
```

Commandline arguments
```bash
-l : Lists all tests
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
|  1 | Check CPUID for Intel CPU                        | :white_check_mark:     |
|  2 | Check CPUID for CPU generation                   | :white_check_mark:     |
|  3 | Check if CPU supports TXT                        | :white_check_mark:     |
|  4 | Check if chipset supports TXT                    | Unimplementable :x:    |
|  5 | Check if TXT registers supports TXT              | :white_check_mark:     |
|  6 | Check CPUID SMX support                          | :white_check_mark:     |
|  7 | Check CPUID VMX support                          | :white_check_mark:     |
|  8 | Check IA\_32FEATURE\_CONTROL bits                | :white_check_mark:     |
|  9 | Check SMX is enabled                             | :white_check_mark:     |
| 10 | Check supported GetSec leaves                    | Unimplementable :x:    |
| 11 | Check TXT not disabled                           | :white_check_mark:     |
| 12 | Check IBB measured                               | :white_check_mark:     |
| 13 | Check firmware trusted                           | :white_check_mark:     |
| 14 | TXT registers are locked                         | :white_check_mark:     |
| 15 | BIOS ACM had no startup error                    | :white_check_mark:     |
| 16 | TPM is present                                   | :white_check_mark:     |
| 17 | TPM is locked                                    | Only TPM 1.2 :clock1:  |
| 18 | TPM PS index set                                 | Only TPM 1.2 :clock1:  |
| 19 | TPM AUX index set                                | Only TPM 1.2 :clock1:  |
| 20 | TPM LCP\_POLICY has set                          | Only TPM 1.2 :clock1:  |
| 21 | TPM PCR0 has been extended                       | Only TPM 1.2 :clock1:  |
| 22 | FIT exists                                       | :white_check_mark:     |
| 23 | FIT contains BIOSACM entry                       | :white_check_mark:     |
| 24 | FIT contains IBB entry                           | :white_check_mark:     |
| 25 | FIT contains BIOS POLICY                         | :white_check_mark:     |
| 26 | FIT IBB covers reset vector                      | :white_check_mark:     |
| 27 | FIT IBB doesn’t overlap IBB                      | :white_check_mark:     |
| 28 | FIT IBBs doesn’t overlap BIOSACM                 | :white_check_mark:     |
| 29 | FIT IBBs and BIOSACM are in 32bit address space  | :white_check_mark:     |
| 30 | FIT TXT\_DISABLE\_POLICY does not disable TXT    | :white_check_mark:     |
| 31 | BIOSACM header is valid                          | :white_check_mark:     |
| 32 | BIOSACM size check                               | :white_check_mark:     |
| 33 | BIOSACM alignment check                          | :white_check_mark:     |
| 34 | BIOSACM matches chipset                          | :white_check_mark:     |
| 35 | BIOSACM matches processor                        | :white_check_mark:     |
| 36 | TXT memory is reserved in e820 map               | :white_check_mark:     |
| 37 | TXT DPR protectes TXT memory                     | :white_check_mark:     |
| 38 | CPU DMA protected range equals hostbridge DPR    | :white_check_mark:     |
| 39 | TXT SINIT in TXT region                          | :white_check_mark:     |
| 40 | TXT SINIT matches chipset                        | :white_check_mark:     |
| 41 | TXT SINIT matches processor                      | :white_check_mark:     |
| 42 | SINIT ACM startup errors                         | :white_check_mark:     |
| 43 | BIOSDATAREGION is present in TXT regions         | :white_check_mark:     |
| 44 | Check CPUID MTRR support                         | :white_check_mark:     |
| 45 | Check MTRRcap for SMRR support                   | :white_check_mark:     |
| 46 | Get SMM/TSEG region                              | :white_check_mark:     |
| 47 | SMRRs are active                                 | :white_check_mark:     |
| 48 | IOMMU/Vt-d is active                             | Todo :clock1:          |
| 49 | TBOOT is active                                  | Todo :clock1:          |
| 50 | Servermode TXT                                   | Todo :clock1:          |
| 51 | FSB Interface is release fused                   | Todo :clock1:          |
| 52 | Memory controller is release fused               | Todo :clock1:          |
