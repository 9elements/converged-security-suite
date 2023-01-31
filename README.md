
![image](assets/logo.png)

The Converged Security Suite implements all necessary tools for Intel platform security features.

| Technology | Testsuite | Provisioning |
| --- | --- | --- |
| Intel Trusted Execution Technology Legacy/CBnT | Supported | Supported |
| Intel Boot Guard 1.0 | WIP | Supported |
| Intel Boot Guard 2.0 | WIP | Supported |
| Intel Platform Firmware Resilience | N/A | Partly Supported |

Build Status
------------
[![CircleCI](https://circleci.com/gh/9elements/converged-security-suite.svg?style=svg)](https://circleci.com/gh/9elements/converged-security-suite)

Tooling & API
-------------

* [Intel TXT Test Suite](cmd/txt-suite) - Test Suite for Intel Trusted Execution Technology validation.
* [Intel TXT Provisioning](cmd/txt-prov) - Provisioning of Trusted Platform Module for Intel Trusted Execution Technology usage.
* [Intel CBnT Provisioning](cmd/bg-prov) - Provisioning of all BootGuard versions and Trusted Execution Technology (CBnT) usage.
* [Intel/AMD pcr0tool](cmd/pcr0tool) - [PCR0](https://security.stackexchange.com/questions/127224/what-does-crtm-refer-to) diagnostics tool.

Developer notes
---------------

If you need to update a Boot Policy Manifest or a Key Manifest then please
read an [instruction](./pkg/intel/metadata/manifest/README.md).

Funding
--------------
<p align="center">
<img src="https://nlnet.nl/logo/banner.svg" height="80">
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;
<img src="https://nlnet.nl/image/logos/NGIAssure_tag.svg" height="80">
</p>

This project was partially funded through the [NGI Assure](https://nlnet.nl/assure) Fund, a fund established by [NLnet](https://nlnet.nl/) with financial support from the European Commission's [Next Generation Internet](https://ngi.eu/) programme, under the aegis of DG Communications Networks, Content and Technology under grant agreement No 957073.
