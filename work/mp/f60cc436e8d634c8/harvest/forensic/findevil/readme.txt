Find Evil tries to identify and discover signs of malware infection.         
Find Evil currently detect some types of malware infection by memory analysis
and does not, at this moment, support anti-virus scans and custom yara rules.
---                                                                          
Find Evil is enabled for 64-bit Windows 10+ to keep false positive ratio low.
Find Evil limit select findings per virtual address decriptor and process to 
keep output manageable. Find Evil also limit findings on select processes.   
---                                                                          
YARA: FindEvil tries to use built-in YARA rules, many which are from         
Elastic Security. The Elastic License 2.0 must be accepted to use the rules. 
https://www.elastic.co/licensing/elastic-license                             
Accept with command line option: '-license-accept-elastic-license-2.0'       
---                                                                          
Documentation:    https://github.com/ufrisk/MemProcFS/wiki/FS_FindEvil       
---                                                                          
Find Evil is a work in progress - post github issues for feature requests.   
