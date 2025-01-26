
![image](assets/logo.png)

The Converged Security Suite implements all necessary tools for Intel platform security features.

| Technology | Testsuite | Provisioning |
| --- | --- | --- |
| Intel Trusted Execution Technology | Supported | Supported |
| Intel Trusted Execution Technology CBnT Extension | Missing | Supported |
| Intel Boot Guard 1.0 | Supported | Supported |
| Intel Boot Guard 2.0 | Supported | Supported |
| Intel Platform Firmware Resilience | N/A | Partly Supported |

Documentation
-------------
[Intel Manifest](https://www.intel.com/content/www/us/en/developer/articles/technical/software-security-guidance/resources/key-usage-in-integrated-firmware-images.html)

Build Status
------------
![Build and Test](https://github.com/9elements/converged-security-suite/actions/workflows/build.yml/badge.svg)

Tooling & API
-------------
**Core Tooling**

* [Intel TXT Test Suite](cmd/core/txt-suite) - Test Suite for Intel Trusted Execution Technology validation.
* [Intel TXT Provisioning](cmd/core/txt-prov) - Provisioning of Trusted Platform Module for Intel Trusted Execution Technology usage.
* [Intel BtG/CBnT Test Suite](cmd/core/bg-suite) - Test Suite for Intel Boot Guard validation.
* [Intel BtG/CBnT Provisioning](cmd/core/bg-prov) - Provisioning of all BootGuard versions and Trusted Execution Technology (CBnT) usage.
* [AMD PSP Test Suite](cmd/core/amd-suite) - Test Suite for AMD Secure Processor validation incl. Secure Boot, AMD SEV and AMD SEV-SNP.

**Experimental Tooling**

* [Intel/AMD pcr0tool](cmd/exp/pcr0tool) - [PCR0](https://security.stackexchange.com/questions/127224/what-does-crtm-refer-to) diagnostics tool.
* [AMD Suite](cmd/exp/amd-suite) - AMD Secure Processor Suite.

Developer notes
---------------

If you need to update a Boot Policy Manifest or a Key Manifest then please
read an
[instruction](https://github.com/linuxboot/fiano/blob/main/pkg/intel/metadata/README.md).

Funding
--------------
<p align="center">
<img src="https://nlnet.nl/logo/banner.svg" height="80">
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;
<img src="https://nlnet.nl/image/logos/NGIAssure_tag.svg" height="80">
</p>

This project was partially funded through the [NGI Assure](https://nlnet.nl/assure) Fund, a fund established by [NLnet](https://nlnet.nl/) with financial support from the European Commission's [Next Generation Internet](https://ngi.eu/) programme, under the aegis of DG Communications Networks, Content and Technology under grant agreement No 957073.
