# Residentmem - Volatility Plugin

`residentmem` for Volatility 2.6 obtains the number of the memory pages resident in memory per module (exe or dll) and per driver from a Windows memory dump.

[![License: GPL v3](https://img.shields.io/badge/License-GPLv3-blue.svg)](https://www.gnu.org/licenses/gpl-3.0)

## Usage

```
residentmem: counts how many memory pages resident in a Windows memory dump per module (exe or dll) and system driver.

    Options:
        -p: Process PID(s)
            (-p 252 | -p 252,452,2852)

        -D DIR, --dump-dir=DIR: Temporary folder to dump output files
        
        --logfile LOGNAME: Logfile to dump full info
            Creates a logfile containing the full output of the tool (for instance, it allows you to obtain the full module names, not truncated as in the Volatility's output
```

## Usage example

```
$ python2 vol.py --plugins /path/to/sum -f /path/to/memory.dump residentmem -D dump-dir
Volatility Foundation Volatility Framework 2.6.1
Pid  Process      Module Name                 Module Base Resident    Total    Path                                           Dump file                                     
---- ------------ -------------------- ------------------ -------- -------- ---------------------------------------------- ----------------------------------------------
 232 smss.exe     smss.exe                     0x47740000       32       32 \SystemRoot\System32\smss.exe                  dump-dir/smss.exe-232-smss.exe.csv         
 232 smss.exe     ntdll.dll                    0x778c0000      287      425 C:\Windows\SYSTEM32\ntdll.dll                  dump-dir/smss.exe-232-ntdll.dll.csv        
 304 csrss.exe    csrss.exe                    0x496a0000        5        6 C:\Windows\system32\csrss.exe                  dump-dir/csrss.exe-304-csrss.exe.csv       
 304 csrss.exe    ntdll.dll                    0x778c0000      273      425 C:\Windows\SYSTEM32\ntdll.dll                  dump-dir/csrss.exe-304-ntdll.dll.csv       
 304 csrss.exe    CSRSRV.dll                0x7fefd890000       15       19 C:\Windows\system32\CSRSRV.dll                 dump-dir/csrss.exe-304-CSRSRV.dll.csv      
 304 csrss.exe    basesrv.DLL               0x7fefd870000       11       17 C:\Windows\system32\basesrv.DLL                dump-dir/csrss.exe-304-basesrv.DLL.csv     
[... redacted ...]    
--   --           ntoskrnl.exe         0xfffff8000265e000     1514     1514 \SystemRoot\system32\ntoskrnl.exe              dump-dir/drv_ntoskrnl.exe.csv              
--   --           hal.dll              0xfffff80002615000       73       73 \SystemRoot\system32\hal.dll                   dump-dir/drv_hal.dll.csv                   
--   --           rdprefmp.sys         0xfffff880015d9000        7        9 \SystemRoot\system32\drivers\rdprefmp.sys      dump-dir/drv_rdprefmp.sys.csv              
--   --           rdpencdd.sys         0xfffff880015d0000        7        9 \SystemRoot\system32\drivers\rdpencdd.sys      dump-dir/drv_rdpencdd.sys.csv              
--   --           kbdclass.sys         0xfffff88002cba000       11       15 \SystemRoot\system32\DRIVERS\kbdclass.sys      dump-dir/drv_kbdclass.sys.csv              
--   --           raspptp.sys          0xfffff8800341b000       30       33 \SystemRoot\system32\DRIVERS\raspptp.sys       dump-dir/drv_raspptp.sys.csv                          
[... redacted ...]
```


## License

Licensed under the [GNU GPLv3](LICENSE) license.
