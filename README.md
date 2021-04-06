
![image](assets/logo.png)

The Converged Security Suite implements all necessary tools for Intel platform security features.

| Technology | Testsuite | Provisioning |
| --- | --- | --- |
| Intel Trusted Execution Technology Legacy | Supported | Supported |
| Intel Trusted Execution Technology CBnT | WIP | Supported |
| Intel Boot Guard | On Hold | On Hold |
| Intel Platform Firmware Resilience | On Hold | - |

Build Status
------------
[![CircleCI](https://circleci.com/gh/9elements/converged-security-suite.svg?style=svg)](https://circleci.com/gh/9elements/converged-security-suite)

Tooling & API
-------------

* [Intel TXT Test Suite](cmd/txt-suite) - Test Suite for Intel Trusted Execution Technology validation.
* [Intel TXT Provisioning](cmd/txt-prov) - Provisioning of Trusted Platform Module for Intel Trusted Execution Technology usage.
* [Intel CBnT Provisioning](cmd/bg-prov) - Provisioning of Converged BootGuard and Trusted Execution Technology (CBnT) usage.
* [pcr0tool](cmd/pcr0tool) - [PCR0](https://security.stackexchange.com/questions/127224/what-does-crtm-refer-to) diagnostics tool.

Developer notes
---------------

If you need to update a Boot Policy Manifest or a Key Manifest then please
read an [instruction](./pkg/intel/metadata/manifest/README.md).
