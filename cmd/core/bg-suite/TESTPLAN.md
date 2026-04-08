Id | Test | Implemented | Document | Chapter | Supported BG/CBnt Version
------------|------------|------------|------------|------------|-----------
00 | FIT meets BootGuard requirements                 | :white_check_mark:     | Document 599500 Revision 1.2 | | 1.0 / 2.0 / 2.1
01 | SACM meets sane BootGuard requirements           | :white_check_mark:     | Document 315168-017          | Chapter A. Authenticated Code Module | 1.0 / 2.0 / 2.1
02 | Key Manifest meets sane BootGuard requirements   | :white_check_mark:     | Document 557867 / 575623     | | 1.0 / 2.0 / 2.1
03 | Boot Policy Manifest meets sane BootGuard requirements | :white_check_mark: | Document 557867 / 575623   | | 1.0 / 2.0 / 2.1
04 | Verifies BPM and IBBs match firmware image       | :white_check_mark:     | Document 557867 / 575623     | | 1.0 / 2.0 / 2.1
05 | [RUNTIME] Validates Intel ME specific configuration against KM/BPM in firmware image | :white_check_mark: | Document 557867 / 575623 | | 1.0 / 2.0
06 | [RUNTIME] Verifies Intel ME Boot Guard status    | :white_check_mark:     | Document 729124 / 829718     | | 2.1
07 | [RUNTIME] Verifies Intel ME Boot Guard configuration is sane and safe | :white_check_mark:     | Document 557867 / 575623 / 829718 / 729124  | 1.0 / 2.0 / 2.1
08 | [RUNTIME] Verifies post-boot ACM status          | :white_check_mark:     | Document 315168-017 / 575623 rev 1.5 | | 1.0 / 2.0
09 | [RUNTIME] Verifies post-boot BtG/TXT registers   | :white_check_mark:     | Document 315168-017 / 575623 rev 1.9 | | 1.0 / 2.0 / 2.1

## Differences in Test Logic Between BG/CBnT 2.0 and CBnT 2.1

Platforms starting from MTL follow CBnT 2.1 specification. This brings additional logic changes in the tests
given above:
 - Test 03: As per Document 575623 rev. 1.9, section 5.3.3.5, PCDE and its sub-structures (PDRS and CBNS) are mandatory
in CBnT 2.1. Therefore on "Validate BPM structure" step, they are also included. Additionally, extending PCR7 to the operating system was deprecated
with MTL, therefore with CBnT 2.1, this check is skipped.
> [!NOTE]
> While this extending PCR7 authority is recommended for older platforms, it breaks the BitLocker on Windows >=10. Thus, it is often not set by the OEM,
> and should be treated as information rather than hard error.

 - Test 05: Platforms that conform to CBnT 2.1 use different specification of Intel ME (18 or above). These do not expose neither
SVN for KM and BPM, nor KMID (see Documents 729124/829718). Therefore, Test 05 for CBnT 2.1 is skipped. Instead, Test 6 is available.
It checks BootGuard status exposed by Intel ME, which is equivalent to runtime validation of BootGuard startup process.

 - Test 07: Similarly as with Test 05, some information are not exposed in Intel ME 18 and above, see below:
    - Bypass Boot Policy
    - Boot Policy validity
    - Error Enforcement Policy
    - Protected BIOS environment status
    - BootGuard disabled bit
  Instead, the following is checked with Intel ME 18 and above:
    - FPF lock
    - Debug Mode status
    - Validity of the bits that follow
    - Whether RCS origin is ACM
    - CPU Debug status
    - ME working state correctness
    - ME operating mode correctness

 - Test 08: The check for ACM status by reading `txtSpace >> 0x328` only gives a meaningful
	results if TXT is disabled in BIOS by the user. Otherwise, the same address will be
	used as `TXT.ERRORCODE` register, and filled with the TXT status. Now given that TXT started
	successfully, bit 31 will change the meaning, i.e. if set, there is some error that we could
	further evaluate, otherwise we shall ignore the rest. Therefore, Test 07 is limited to BG 1.0
  and CBnT 2.0.

- Test 09: Available for all specifications, same as Test 08, but without the ACM status check if TXT is enabled, and
with the additional checks of BootStatus register, namely:
    - Boot Guard startup status
    - whether BIOS is considered trusted
    - whether CPU error occurred
    - SACM startup status.
