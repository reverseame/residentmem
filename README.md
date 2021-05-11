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
Pid  Process      Module Name          File Version   Module Base Resident Total    Path                                           Dump file                                     
---- ------------ -------------------- -------------- ----------- -------- -------- ---------------------------------------------- --------------------------------------
 216 smss.exe     smss.exe                             0x476e0000       17       19 \SystemRoot\System32\smss.exe                  dump-dir/smss.exe-216-smss.exe.csv     
 216 smss.exe     ntdll.dll                            0x76da0000      112      316 C:\Windows\SYSTEM32\ntdll.dll                  dump-dir/smss.exe-216-ntdll.dll.csv    
 288 csrss.exe    csrss.exe            6.1.7600.16385  0x4a510000        4        5 C:\Windows\system32\csrss.exe                  dump-dir/csrss.exe-288-csrss.exe.csv    
 288 csrss.exe    basesrv.DLL                          0x74f40000       10       14 C:\Windows\system32\basesrv.DLL                dump-dir/csrss.exe-288-basesrv.DLL.csv  
 288 csrss.exe    winsrv.DLL           6.1.7601.17514  0x74f10000       11       44 C:\Windows\system32\winsrv.DLL                 dump-dir/csrss.exe-288-winsrv.DLL.csv   
 288 csrss.exe    USER32.dll           6.1.7601.17514  0x758d0000       66      201 C:\Windows\system32\USER32.dll                 dump-dir/csrss.exe-288-USER32.dll.csv   
[... redacted ...] 
--   --           USBD.SYS             6.1.7600.16385  0x9279b000        2        2 \SystemRoot\system32\DRIVERS\USBD.SYS          dump-dir/drv_USBD.SYS.csv
--   --           termdd.sys                           0x8cb7c000       14       17 \SystemRoot\system32\DRIVERS\termdd.sys        dump-dir/drv_termdd.sys.csv
--   --           pacer.sys                            0x8cc00000       19       31 \SystemRoot\system32\DRIVERS\pacer.sys         dump-dir/drv_pacer.sys.csv
--   --           HIDCLASS.SYS         6.1.7601.17514  0x92781000       19       19 \SystemRoot\system32\DRIVERS\HIDCLASS.SYS      dump-dir/drv_HIDCLASS.SYS.csv
--   --           dump_pciidex.sys     6.1.7600.16385  0x92750000       11       11 \SystemRoot\System32\Drivers\dump_dumpata.sys  dump-dir/drv_dump_dumpata.sys.csv
--   --           VIDEOPRT.SYS         6.1.7600.16385  0x8cf14000       33       33 \SystemRoot\System32\drivers\VIDEOPRT.SYS      dump-dir/drv_VIDEOPRT.SYS.csv
[... redacted ...]
```


## License

Licensed under the [GNU GPLv3](LICENSE) license.
