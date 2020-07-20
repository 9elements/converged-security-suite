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
13 | TPM 1.2 present                                  | :white_check_mark:     |                              |                                                         
14 | TPM 2.0 is present                               | :white_check_mark:     |                              |                                                         
15 | TPM is present                                   | :white_check_mark:     |                              |                                                         
16 | TPM NVRAM is locked                              | :white_check_mark:     | Document 558294 Revision 2.0 | 5.6.3.1 Failsafe Hash                                   
17 | PS Index has correct config                      | :white_check_mark:     | Document 315168-016          | I TPM NV                                                
18 | AUX Index has correct config                     | :white_check_mark:     | Document 315168-016          | I TPM NV                                                
19 | AUX Index has the correct hash                   | :white_check_mark:     | Document 315168-016          | I TPM NV                                                
20 | PO Index has correct config                      | :white_check_mark:     | Document 315168-016          | I TPM NV                                                
21 | PS index has valid LCP Policy                    | :white_check_mark:     | Document 315168-016          | D.3 LCP_POLICY_LIST                                     
22 | PO index has valid LCP Policy                    | :white_check_mark:     | Document 315168-016          | D.3 LCP_POLICY_LIST                                     
23 | PCR 0 is set correctly                           | :white_check_mark:     | Document 558294 Revision 2.0 | BIOS Startup Module (Type 0x07) Entry                   
24 | NPW mode is deactivated in PS policy             | :white_check_mark:     | Document 558294 Revision 2.0 | 4.1.4 Supported Platform Configurations                 
25 | Auto-promotion mode is active                    | :white_check_mark:     | Document 558294 Revision 2.0 | 5.6.2 Autopromotion Hash and Signed BIOS Policy         
26 | Signed policy mode is active                     | :white_check_mark:     | Document 558294 Revision 2.0 | 5.6.2 Autopromotion Hash and Signed BIOS Policy         
27 | Valid FIT vector                                 | :white_check_mark:     | Document 599500 Revision 1.2 | 3.0 FIT Pointer                                         
28 | Valid FIT                                        | :white_check_mark:     | Document 599500 Revision 1.2 | 4.0 Firmware Interface Table                            
29 | Microcode update entry in FIT                    | :white_check_mark:     | Document 599500 Revision 1.2 | 4.4 Startup ACM (Type 2) Rules                          
30 | BIOS ACM entry in FIT                            | :white_check_mark:     | Document 599500 Revision 1.2 | 4.4 Startup ACM (Type 2) Rules                          
31 | IBB entry in FIT                                 | :white_check_mark:     | Document 599500 Revision 1.2 | 4.6 BIOS Startup Module (Type 7) Rules                  
32 | BIOS Policy entry in FIT                         | :white_check_mark:     |                              |                                                         
33 | IBB covers reset vector                          | :white_check_mark:     | Document 599500 Revision 1.2 | 4.6 BIOS Startup Module (Type 7) Rules                  
34 | IBB covers FIT vector                            | :white_check_mark:     | Document 599500 Revision 1.2 | 4.6 BIOS Startup Module (Type 7) Rules                  
35 | IBB covers FIT                                   | :white_check_mark:     |                              |                                                         
36 | IBBs doesn't overlap each other                  | :white_check_mark:     | Document 599500 Revision 1.2 | 4.6 BIOS Startup Module (Type 7) Rules                  
37 | BIOS ACM does not overlap IBBs                   | :white_check_mark:     | Document 599500 Revision 1.2 | 4.6 BIOS Startup Module (Type 7) Rules                  
38 | IBB and BIOS ACM below 4GiB                      | :white_check_mark:     | Document 558294 Revision 2.0 | 2.2 FIT Pointer Rules                                   
39 | TXT not disabled by LCP Policy                   | :white_check_mark:     | Document 315168-016          | B.1.6 TXT.SPAD – BOOTSTATUS                             
40 | BIOSACM header valid                             | :white_check_mark:     | Document 315168-016          | A.1 Authenticated Code Module Format                    
41 | BIOSACM size check                               | :white_check_mark:     | Document 315168-016          | A.1 Authenticated Code Module Format                    
42 | BIOSACM alignment check                          | :white_check_mark:     | Document 315168-016          | A.1.1 Memory Type Cacheability Restrictions             
43 | BIOSACM matches chipset                          | :white_check_mark:     | Document 315168-016          | 2.2.3.1 Matching an AC Module to the Platform           
44 | BIOSACM matches processor                        | :white_check_mark:     | Document 315168-016          | 2.2.3.1 Matching an AC Module to the Platform           
45 | SINIT/BIOS ACM has no NPW flag set               | :white_check_mark:     | Document 558294 Revision 2.0 | 4.1.4 Supported Platform Configurations                 
46 | TXT memory ranges valid                          | :white_check_mark:     | Document 315168-016          | B.1                                                     
47 | TXT public area reserved in e820                 | :white_check_mark:     | Document 558294 Revision 2.0 | 5.5.3 Intel TXT Public Space                            
48 | TXT memory reserved in e820                      | :white_check_mark:     | Document 558294 Revision 2.0 | 5.5.4 TPM Decode Area                                   
49 | MMIO TPMDecode space reserved in e820            | :white_check_mark:     | Document 558294 Revision 2.0 | 5.5.4 TPM Decode Area                                   
50 | TXT memory in a DMA protected range              | :white_check_mark:     | Document 315168-016          | 1.11.1 DMA Protected Range (DPR)                        
51 | TXT DPR register locked                          | :white_check_mark:     | Document 315168-016          | 1.11.1 DMA Protected Range (DPR)                        
52 | CPU DPR equals hostbridge DPR                    | :white_check_mark:     | Document 315168-016          | B 1.15 TXT.DPR – DMA Protected Range                    
53 | CPU hostbridge DPR register locked               | :white_check_mark:     | Document 315168-016          | B 1.15 TXT.DPR – DMA Protected Range                    
54 | TXT region contains SINIT ACM                    | :white_check_mark:     | Document 315168-016          | B 1.10 TXT.SINIT.BASE – SINIT Base Address              
55 | SINIT ACM matches chipset                        | :white_check_mark:     | Document 315168-016          | 2.2.3.1 Matching an AC Module to the Platform           
56 | SINIT ACM matches CPU                            | :white_check_mark:     | Document 315168-016          | 2.2.3.1 Matching an AC Module to the Platform           
57 | SINIT ACM startup successful                     | :white_check_mark:     |                              |                                                         
58 | BIOS DATA REGION present                         | :white_check_mark:     | Document 315168-016          | C.2 BIOS Data Format                                    
59 | BIOS DATA REGION valid                           | :white_check_mark:     | Document 315168-016          | C.2 BIOS Data Format                                    
60 | CPU supports MTRRs                               | :white_check_mark:     | Document 315168-016          | 2.2.5.1 MTRR Setup Prior to GETSEC[SENTER] Execution    
61 | CPU supports SMRRs                               | :white_check_mark:     |                              |                                                         
62 | SMRR covers SMM memory                           | :white_check_mark:     |                              |                                                         
63 | SMRR protection active                           | :white_check_mark:     |                              |                                                         
64 | IOMMU/VT-d active                                | :white_check_mark:     | Document 315168-016          | 1.11.2 Protected Memory Regions (PMRs)                  
65 | TXT server mode enabled                          | :white_check_mark:     |                              |                                                         
