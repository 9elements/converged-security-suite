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
11 | IA32 debug interface isn't disabled              | :white_check_mark:     |                              |                                                         
12 | TPM connection                                   | :white_check_mark:     |                              |                                                         
13 | TPM 1.2 present                                  | :white_check_mark:     |                              |                                                         
14 | TPM 2.0 is present                               | :white_check_mark:     |                              |                                                         
15 | TPM is present                                   | :white_check_mark:     |                              |                                                         
16 | TPM NVRAM is locked                              | :white_check_mark:     | Document 558294 Revision 2.0 | 5.6.3.1 Failsafe Hash                                   
17 | PS Index has correct config                      | :white_check_mark:     | Document 315168-016          | I TPM NV                                                
18 | AUX Index has correct config                     | :white_check_mark:     | Document 315168-016          | I TPM NV                                                
19 | PO Index has correct config                      | :white_check_mark:     | Document 315168-016          | I TPM NV                                                
20 | PS index has valid LCP Policy                    | :white_check_mark:     | Document 315168-016          | D.3 LCP_POLICY_LIST                                     
21 | PO index has valid LCP Policy                    | :white_check_mark:     | Document 315168-016          | D.3 LCP_POLICY_LIST                                     
22 | PCR 0 is set correctly                           | :white_check_mark:     | Document 558294 Revision 2.0 | BIOS Startup Module (Type 0x07) Entry                   
23 | NPW mode is deactivated in PS policy             | :white_check_mark:     | Document 558294 Revision 2.0 | 4.1.4 Supported Platform Configurations                 
24 | Auto-promotion mode is active                    | :white_check_mark:     | Document 558294 Revision 2.0 | 5.6.2 Autopromotion Hash and Signed BIOS Policy         
25 | Signed policy mode is active                     | :white_check_mark:     | Document 558294 Revision 2.0 | 5.6.2 Autopromotion Hash and Signed BIOS Policy         
26 | Valid FIT vector                                 | :white_check_mark:     | Document 599500 Revision 1.2 | 3.0 FIT Pointer                                         
27 | Valid FIT                                        | :white_check_mark:     | Document 599500 Revision 1.2 | 4.0 Firmware Interface Table                            
28 | BIOS ACM entry in FIT                            | :white_check_mark:     | Document 599500 Revision 1.2 | 4.4 Startup ACM (Type 2) Rules                          
29 | IBB entry in FIT                                 | :white_check_mark:     | Document 599500 Revision 1.2 | 4.6 BIOS Startup Module (Type 7) Rules                  
30 | BIOS Policy entry in FIT                         | :white_check_mark:     |                              |                                                         
31 | IBB covers reset vector                          | :white_check_mark:     | Document 599500 Revision 1.2 | 4.6 BIOS Startup Module (Type 7) Rules                  
32 | IBB covers FIT vector                            | :white_check_mark:     | Document 599500 Revision 1.2 | 4.6 BIOS Startup Module (Type 7) Rules                  
33 | IBB covers FIT                                   | :white_check_mark:     |                              |                                                         
34 | IBBs doesn't overlap each other                  | :white_check_mark:     | Document 599500 Revision 1.2 | 4.6 BIOS Startup Module (Type 7) Rules                  
35 | BIOS ACM does not overlap IBBs                   | :white_check_mark:     | Document 599500 Revision 1.2 | 4.6 BIOS Startup Module (Type 7) Rules                  
36 | IBB and BIOS ACM below 4GiB                      | :white_check_mark:     | Document 558294 Revision 2.0 | 2.2 FIT Pointer Rules                                   
37 | TXT not disabled by LCP Policy                   | :white_check_mark:     | Document 315168-016          | B.1.6 TXT.SPAD – BOOTSTATUS                             
38 | BIOSACM header valid                             | :white_check_mark:     | Document 315168-016          | A.1 Authenticated Code Module Format                    
39 | BIOSACM size check                               | :white_check_mark:     | Document 315168-016          | A.1 Authenticated Code Module Format                    
40 | BIOSACM alignment check                          | :white_check_mark:     | Document 315168-016          | A.1.1 Memory Type Cacheability Restrictions             
41 | BIOSACM matches chipset                          | :white_check_mark:     | Document 315168-016          | 2.2.3.1 Matching an AC Module to the Platform           
42 | BIOSACM matches processor                        | :white_check_mark:     | Document 315168-016          | 2.2.3.1 Matching an AC Module to the Platform           
43 | SINIT/BIOS ACM has no NPW flag set               | :white_check_mark:     | Document 558294 Revision 2.0 | 4.1.4 Supported Platform Configurations                 
44 | TXT memory ranges valid                          | :white_check_mark:     | Document 315168-016          | B.1                                                     
45 | TXT memory reserved in e820                      | :white_check_mark:     | Document 558294 Revision 2.0 | 5.5.4 TPM Decode Area                                   
46 | TXT memory in a DMA protected range              | :white_check_mark:     | Document 315168-016          | 1.11.1 DMA Protected Range (DPR)                        
47 | TXT DPR register locked                          | :white_check_mark:     | Document 315168-016          | 1.11.1 DMA Protected Range (DPR)                        
48 | CPU DPR equals hostbridge DPR                    | :white_check_mark:     | Document 315168-016          | B 1.15 TXT.DPR – DMA Protected Range                    
49 | CPU hostbridge DPR register locked               | :white_check_mark:     | Document 315168-016          | B 1.15 TXT.DPR – DMA Protected Range                    
50 | TXT region contains SINIT ACM                    | :white_check_mark:     | Document 315168-016          | B 1.10 TXT.SINIT.BASE – SINIT Base Address              
51 | SINIT ACM matches chipset                        | :white_check_mark:     | Document 315168-016          | 2.2.3.1 Matching an AC Module to the Platform           
52 | SINIT ACM matches CPU                            | :white_check_mark:     | Document 315168-016          | 2.2.3.1 Matching an AC Module to the Platform           
53 | SINIT ACM startup successful                     | :white_check_mark:     |                              |                                                         
54 | BIOS DATA REGION present                         | :white_check_mark:     | Document 315168-016          | C.2 BIOS Data Format                                    
55 | BIOS DATA REGION valid                           | :white_check_mark:     | Document 315168-016          | C.2 BIOS Data Format                                    
56 | CPU supports MTRRs                               | :white_check_mark:     | Document 315168-016          | 2.2.5.1 MTRR Setup Prior to GETSEC[SENTER] Execution    
57 | CPU supports SMRRs                               | :white_check_mark:     |                              |                                                         
58 | SMRR covers SMM memory                           | :white_check_mark:     |                              |                                                         
59 | SMRR protection active                           | :white_check_mark:     |                              |                                                         
60 | IOMMU/VT-d active                                | :white_check_mark:     | Document 315168-016          | 1.11.2 Protected Memory Regions (PMRs)                  
61 | TXT server mode enabled                          | :white_check_mark:     |                              |                                                         
