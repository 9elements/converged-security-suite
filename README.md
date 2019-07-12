TPM/TXT Validation Test Suite
=============================

This Golang utility tests whether the platform supports Intel TXT and FIT, TPM
boot chain has been configured correctly.

The suite is work in progress.

Usage
-----

The test suite runs on GNU/Linux. The `/dev/mem` device must allow access to the
full physical memory. You may have to add the following to the kernel command line:

```bash
iomem=relaxed strict-devmem=0 mem.devmem=1
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

Tests
-----

The test suite implements the following tests.

|  # | Test                                             | Implementation status |
| -- | ------------------------------------------------ | --------------------- |
|  1 | Check CPUID for Intel CPU                        | :white_check_mark:    |
|  2 | Check CPUID for CPU generation                   | :white_check_mark:    |
|  3 | Check if CPU supports TXT                        | :white_check_mark:    |
|  4 | Check if chipset supports TXT                    | :white_check_mark:    |
|  5 | Check if TXT registers supports TXT              | :white_check_mark:    |
|  6 | Check CPUID SMX support                          | :white_check_mark:    |
|  7 | Check CPUID VMX support                          | :white_check_mark:    |
|  8 | Check IA\_32FEATURE\_CONTROL bits                | :white_check_mark:    |
|  9 | Check SMX is enabled                             | :white_check_mark:    |
| 10 | Check supported GetSec leaves                    | :white_check_mark:    |
| 11 | Check TXT not disabled                           | :white_check_mark:    |
| 12 | Check IBB measured                               | :white_check_mark:    |
| 13 | Check firmware trusted                           | :white_check_mark:    |
| 14 | TXT registers are locked                         | :white_check_mark:    |
| 15 | BIOS ACM had no startup error                    | :white_check_mark:    |
| 16 | TPM is present                                   | :white_check_mark:    |
| 17 | TPM is locked                                    | :white_check_mark:    |
| 18 | TPM PS index set                                 | :white_check_mark:    |
| 19 | TPM AUX index set                                | :white_check_mark:    |
| 20 | TPM LCP\_POLICY has set                          | :white_check_mark:    |
| 21 | TPM PCR0 has been extended                       | :white_check_mark:    |
| 22 | FIT exists                                       | :white_check_mark:    |
| 23 | FIT contains BIOSACM entry                       | :white_check_mark:    |
| 24 | FIT contains IBB entry                           | :white_check_mark:    |
| 25 | FIT contains BIOS POLICY                         | :white_check_mark:    |
| 26 | FIT IBB covers reset vector                      | :white_check_mark:    |
| 27 | FIT IBB doesn’t overlap IBB                      | :white_check_mark:    |
| 28 | FIT IBBs doesn’t overlap BIOSACM                 | :white_check_mark:    |
| 29 | FIT IBBs and BIOSACM are in 32bit address space  | :white_check_mark:    |
| 30 | FIT TXT\_DISABLE\_POLICY does not disable TXT    | :white_check_mark:    |
| 31 | BIOSACM header is valid                          | :white_check_mark:    |
| 32 | BIOSACM size check                               | :white_check_mark:    |
| 33 | BIOSACM alignment check                          | :white_check_mark:    |
| 34 | BIOSACM matches chipset                          | :white_check_mark:    |
| 35 | BIOSACM matches processor                        | :white_check_mark:    |
| 36 | TXT memory is reserved in e820 map               | :white_check_mark:    |
| 37 | TXT DPR protectes TXT memory                     | :white_check_mark:    |
| 38 | CPU DMA protected range equals hostbridge DPR    | :white_check_mark:    |
| 39 | TXT SINIT in TXT region                          | :white_check_mark:    |
| 40 | TXT SINIT matches chipset                        | :white_check_mark:    |
| 41 | TXT SINIT matches processor                      | :white_check_mark:    |
| 42 | SINIT ACM startup errors                         | :white_check_mark:    |
| 43 | BIOSDATAREGION is present in TXT regions         | :white_check_mark:    |
| 44 | Check CPUID MTRR support                         | :white_check_mark:    |
| 45 | Check MTRRcap for SMRR support                   | :white_check_mark:    |
| 46 | Get SMM/TSEG region                              | :white_check_mark:    |
| 47 | SMRRs are active                                 | :white_check_mark:    |
| 48 | IOMMU/Vt-d is active                             | :clock1: todo         |
| 49 | TBOOT is active                                  | :clock1: todo         |
| 50 | Servermode TXT                                   | :clock1: todo         |
| 51 | FSB Interface is release fused                   | :clock1: todo         |
| 52 | Memory controller is release fused               | :clock1: todo         |
