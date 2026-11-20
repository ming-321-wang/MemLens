Information about MemProcFS forensics:                                      
======================================                                      
MemProcFS forensics is a collection of batch oriented comprehensive analysis
tasks that may be initiated by the user.                                    
                                                                            
PLEASE NOTE: Forensic analysis of live memory (FPGA, WinPMEM, VMWARE, etc.) 
is supported but not recommended. Severe memory drift/smear will occur and  
may severely affect results over time. Run at your own risk!                
                                                                            
MemProcFS forensics performs the batch oriented comprehensive analysis tasks
and outputs the result into a sqlite database and displays the result in the
forensic sub-directory. Analysis tasks include (but are not limited to):    
 - NTFS MFT scanning.                                                       
 - Timeline analysis of Processes, Registry, NTFS MFT, Plugins and more.    
                                                                            
MemProcFS forensics is initialized by changing the file forensic_enable.txt.
Once forensic_enable.txt is updated initialization of MemProcFS forensics   
will take place. This may take some time due to scanning of the whole memory
image and timeline construction.                                            
If possible the file name of the sqlite will show in database.txt.          
Valid initialization values for forensic_enable.txt are listed below:       
 1 = in-memory sqlite database.                                             
 2 = temporary sqlite database which will be deleted upon MemProcFS exit.   
 3 = temporary sqlite database which will remain upon MemProcFS exit.       
 4 = static named sqlite database (vmm.sqlite3).                            
Note! MemProcFS forensics may take some time to initialize. Once intialized 
sub-directories under the forensic directory will show up automatically.    
                                                                            
FORENSIC FILE CONSISTENCY: Due to MemProcFS fast multi-threading & caching  
forensic results may differ (primarily different order). To avoid this start
MemProcFS with the -forensic <mode> startup option. If targeting memory from
local file greater consistency will be enabled from the start.              
                                                                            
For additional information about MemProcFS forensics check out the guide at:
https://github.com/ufrisk/MemProcFS/wiki                                    
