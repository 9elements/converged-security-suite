Intel BtG/CBnT Validation Test Suite
====================================

This Golang utility tests whether the platform supports Intel BtG/CBnT and FIT
boot chain has been configured correctly under x86_64 linux.
The only supported architecture is x86_64.

[![GitHub Releases](https://img.shields.io/github/downloads/9elements/converged-security-suite/v2.0/total?label=Download%20v2.0&style=for-the-badge)](https://github.com/9elements/converged-security-suite/releases/latest/download/bg-suite)

Prerequisites for Usage
-----------------------
Supported OS: Any Linux distribution

**1. Load the MSR kernel module.**

Load the *msr* kernel module:
```bash
modprobe msr
```

**2. Execute the txt-suite.**

```bash
sudo chmod +x bg-suite && sudo ./bg-suite
```

Commandline arguments
```bash
Usage: bg-suite <command>

Intel BtG/CBnT Test Suite

Flags:
  -h, --help                           Show context-sensitive help.
      --manifest-strict-order-check    Enable checking of manifest elements order
  -t, --file-path=STRING               Select firmware image filepath

Commands:
  exec-tests    Executes tests given be TestNo or TestSet
  list          Lists all tests
  markdown      Output test implementation state as Markdown
  version       Prints the version of the program

Run "bg-suite <command> --help" for more information on a command.

bg-suite: error: expected one of "exec-tests",  "list",  "markdown",  "version"
```

Tests
-----

Please take a look at the [TESTPLAN](TESTPLAN.md).
