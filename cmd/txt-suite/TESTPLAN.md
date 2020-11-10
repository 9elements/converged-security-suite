Id | Test | Implemented | Document | Chapter
------------|------------|------------|------------|------------
00 | Intel CPU                                        | :white_check_mark:     |                              |                                                         
01 | Weybridge or later                               | :white_check_mark:     |                              |                                                         
02 | CPU supports TXT                                 | :white_check_mark:     |                              |                                                         
03 | TXT register space accessible                    | :white_check_mark:     |                              |                                                         
04 | CPU supports SMX                                 | :white_check_mark:     | Document 558294 Revision 2.0 | 5.4.2 GETSEC Capability Control                         
05 | CPU supports VMX                                 | :white_check_mark:     |                              |                                                         
06 | IA32_FEATURE_CONTROL                             | :white_check_mark:     | Document 558294 Revision 2.0 | 5.4.1 Intel TXT Opt-In Control                          
07 | TXT not disabled by BIOS                         | :white_check_mark:     | Document 558294 Revision 2.0 | 5.4.1 Intel TXT Opt-In Control                          
08 | BIOS ACM has run                                 | :white_check_mark:     | Document 315168-016          | B.1.6 TXT.SPAD – BOOTSTATUS                             
09 | IBB is trusted                                   | :white_check_mark:     | Document 315168-016          | B.1.6 TXT.SPAD – BOOTSTATUS                             
10 | TXT registers are locked                         | :white_check_mark:     |                              |                                                         
11 | IA32 debug interface is disabled                 | :white_check_mark:     |                              |                                                         
12 | TPM connection                                   | :white_check_mark:     |                              |                                                         
13 | TPM is present                                   | :white_check_mark:     |                              |                                                         
14 | TPM NVRAM is locked                              | :white_check_mark:     | Document 558294 Revision 2.0 | 5.6.3.1 Failsafe Hash                                   
15 | PS Index has correct config                      | :white_check_mark:     | Document 315168-016          | I TPM NV                                                
16 | AUX Index has correct config                     | :white_check_mark:     | Document 315168-016          | I TPM NV                                                
17 | AUX Index has the correct hash                   | :white_check_mark:     | Document 315168-016          | I TPM NV                                                
18 | PO Index has correct config                      | :white_check_mark:     | Document 315168-016          | I TPM NV                                                
19 | PS index has valid LCP Policy                    | :white_check_mark:     | Document 315168-016          | D.3 LCP_POLICY_LIST                                     
20 | PO index has valid LCP Policy                    | :white_check_mark:     | Document 315168-016          | D.3 LCP_POLICY_LIST                                     
21 | PCR 0 is set correctly                           | :white_check_mark:     | Document 558294 Revision 2.0 | BIOS Startup Module (Type 0x07) Entry                   
22 | NPW mode is deactivated in PS policy             | :white_check_mark:     | Document 558294 Revision 2.0 | 4.1.4 Supported Platform Configurations                 
23 | TXT mode is valid                                | :white_check_mark:     | Document 558294 Revision 2.0 | 5.6.2 Autopromotion Hash and Signed BIOS Policy         
24 | Valid FIT vector                                 | :white_check_mark:     | Document 599500 Revision 1.2 | 3.0 FIT Pointer                                         
25 | Valid FIT                                        | :white_check_mark:     | Document 599500 Revision 1.2 | 4.0 Firmware Interface Table                            
26 | Microcode update entry in FIT                    | :white_check_mark:     | Document 599500 Revision 1.2 | 4.4 Startup ACM (Type 2) Rules                          
27 | BIOS ACM entry in FIT                            | :white_check_mark:     | Document 599500 Revision 1.2 | 4.4 Startup ACM (Type 2) Rules                          
28 | IBB entry in FIT                                 | :white_check_mark:     | Document 599500 Revision 1.2 | 4.6 BIOS Startup Module (Type 7) Rules                  
29 | BIOS Policy entry in FIT                         | :white_check_mark:     |                              |                                                         
30 | IBB covers reset vector                          | :white_check_mark:     | Document 599500 Revision 1.2 | 4.6 BIOS Startup Module (Type 7) Rules                  
31 | IBB covers FIT vector                            | :white_check_mark:     | Document 599500 Revision 1.2 | 4.6 BIOS Startup Module (Type 7) Rules                  
32 | IBB covers FIT                                   | :white_check_mark:     |                              |                                                         
33 | IBBs doesn't overlap each other                  | :white_check_mark:     | Document 599500 Revision 1.2 | 4.6 BIOS Startup Module (Type 7) Rules                  
34 | BIOS ACM does not overlap IBBs                   | :white_check_mark:     | Document 599500 Revision 1.2 | 4.6 BIOS Startup Module (Type 7) Rules                  
35 | IBB and BIOS ACM below 4GiB                      | :white_check_mark:     | Document 558294 Revision 2.0 | 2.2 FIT Pointer Rules                                   
36 | TXT not disabled by LCP Policy                   | :white_check_mark:     | Document 315168-016          | B.1.6 TXT.SPAD – BOOTSTATUS                             
37 | BIOSACM header valid                             | :white_check_mark:     | Document 315168-016          | A.1 Authenticated Code Module Format                    
38 | BIOSACM size check                               | :white_check_mark:     | Document 315168-016          | A.1 Authenticated Code Module Format                    
39 | BIOSACM alignment check                          | :white_check_mark:     | Document 315168-016          | A.1.1 Memory Type Cacheability Restrictions             
40 | BIOSACM matches chipset                          | :white_check_mark:     | Document 315168-016          | 2.2.3.1 Matching an AC Module to the Platform           
41 | BIOSACM matches processor                        | :white_check_mark:     | Document 315168-016          | 2.2.3.1 Matching an AC Module to the Platform           
42 | SINIT/BIOS ACM has no NPW flag set               | :white_check_mark:     | Document 558294 Revision 2.0 | 4.1.4 Supported Platform Configurations                 
43 | SINIT ACM supports used TPM                      | :white_check_mark:     | Document 315168-016          | 4.1.4 Supported Platform Configurations                 
44 | TXT heap ranges valid                            | :white_check_mark:     | Document 315168-016          | B.1                                                     
45 | TXT public area reserved in e820                 | :white_check_mark:     | Document 558294 Revision 2.0 | 5.5.3 Intel TXT Public Space                            
46 | TXT private area reserved in e820                | :white_check_mark:     | Document 558294 Revision 2.0 | 5.5.2 Intel TXT Private Space                           
47 | TXT memory reserved in e820                      | :white_check_mark:     | Document 558294 Revision 2.0 | 5.5.4 Intel TPM Decode Area                             
48 | MMIO TPMDecode space reserved in e820            | :white_check_mark:     | Document 558294 Revision 2.0 | 5.5.4 TPM Decode Area                                   
49 | TXT memory in a DMA protected range              | :white_check_mark:     | Document 315168-016          | 1.11.1 DMA Protected Range (DPR)                        
50 | TXT DPR register locked                          | :white_check_mark:     | Document 315168-016          | 1.11.1 DMA Protected Range (DPR)                        
51 | CPU DPR equals hostbridge DPR                    | :white_check_mark:     | Document 315168-016          | B 1.15 TXT.DPR – DMA Protected Range                    
52 | CPU hostbridge DPR register locked               | :white_check_mark:     | Document 315168-016          | B 1.15 TXT.DPR – DMA Protected Range                    
53 | TXT region contains SINIT ACM                    | :white_check_mark:     | Document 315168-016          | B 1.10 TXT.SINIT.BASE – SINIT Base Address              
54 | SINIT ACM matches chipset                        | :white_check_mark:     | Document 315168-016          | 2.2.3.1 Matching an AC Module to the Platform           
55 | SINIT ACM matches CPU                            | :white_check_mark:     | Document 315168-016          | 2.2.3.1 Matching an AC Module to the Platform           
56 | SINIT ACM startup successful                     | :white_check_mark:     |                              |                                                         
57 | BIOS DATA REGION present                         | :white_check_mark:     | Document 315168-016          | C.2 BIOS Data Format                                    
58 | BIOS DATA REGION valid                           | :white_check_mark:     | Document 315168-016          | C.2 BIOS Data Format                                    
59 | CPU supports MTRRs                               | :white_check_mark:     | Document 315168-016          | 2.2.5.1 MTRR Setup Prior to GETSEC[SENTER] Execution    
60 | CPU supports SMRRs                               | :white_check_mark:     |                              |                                                         
61 | SMRR covers SMM memory                           | :white_check_mark:     |                              |                                                         
62 | SMRR protection active                           | :white_check_mark:     |                              |                                                         
63 | IOMMU/VT-d active                                | :white_check_mark:     | Document 315168-016          | 1.11.2 Protected Memory Regions (PMRs)                  
64 | TXT server mode enabled                          | :white_check_mark:     |                              |                                                         
65 | ACPI RSDP exists and has valid checksum          | :white_check_mark:     |                              | SINIT Class 0xC Major 1                                 
66 | ACPI MCFG is present                             | :white_check_mark:     |                              | SINIT Class 0xC Major 0xa                               
67 | ACPI DMAR is present                             | :white_check_mark:     |                              | SINIT Class 0xC Major 4                                 
68 | ACPI DMAR is valid                               | :white_check_mark:     |                              | SINIT Class 0xC Major 5                                 
69 | ACPI MADT is present                             | :white_check_mark:     |                              | SINIT Class 0xC Major 16                                
70 | ACPI MADT is valid                               | :white_check_mark:     |                              | SINIT Class 0xC Major 7                                 
71 | ACPI RSDT present                                | :x:                    |                              | SINIT Class 0xC Major 2                                 
72 | ACPI RSDT is valid                               | :white_check_mark:     |                              | SINIT Class 0xC Major 3                                 
73 | ACPI XSDT present                                | :white_check_mark:     |                              | SINIT Class 0xC Major 9                                 
74 | ACPI XSDT is valid                               | :white_check_mark:     |                              | SINIT Class 0xC Major 9                                 
75 | ACPI RSDT or XSDT is valid                       | :white_check_mark:     |                              | 5.2.8 Extended System Description Table (XSDT)          
