Bitlocker plugin for MemProcFS:                                             
===============================                                             
                                                                            
The BitLocker plugin tries to recover BitLocker key material from memory.   
                                                                            
The MemProcFS BitLocker plugin is to some degree inspired by the excellent  
Volatility plugin at: https://github.com/breppo/Volatility-BitLocker        
                                                                            
To mount a bitlocker drive please use Linux dislocker. You may mount with   
the recovered key material in the .fvek file by:                            
dislocker -k <recovered_key>.fvek /path/to/disk /path/to/dislocker          
mount /path/to/dislocker/dislocker-file /path/to/mount                      
                                                                            
The plugin works best analyzing Windows 7 and Windows 10/11 targets.        
Windows 8 support is more error prone - but will most often work.           
---                                                                         
Documentation: https://github.com/ufrisk/MemProcFS/wiki/FS_BitLocker        
