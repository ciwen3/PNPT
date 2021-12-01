# Unquoted Path Vulnerability
## Use:

make a copy of a standalone putty and rename as C:\program.exe and c:\program files\common.exe

When putty randomly pops up, open up CMD as **administrator**. 

## Run the following:
```
wmic process where name="program.exe" get commandline
wmic process where name="program.exe" get parentprocessid
wmic process where processid=<id number from previous command> get commandline
```

## Example:
```
Microsoft Windows [Version 10.0.18362.959]
(c) 2019 Microsoft Corporation. All rights reserved.

C:\WINDOWS\system32>wmic process where name="program.exe" get commandline
CommandLine
C:\Program Files (x86)\Common Files\Adobe\AdobeGCClient\AGSService.exe \\.\pipe\gc_pipe_zzkhfm


C:\WINDOWS\system32>wmic process where name="program.exe" get parentprocessid
ParentProcessId
24324


C:\WINDOWS\system32>wmic process where processid=24324 get commandline
CommandLine
"C:\Program Files (x86)\Common Files\Adobe\AdobeGCClient\AGSService.exe"


C:\WINDOWS\system32>
```

## References:
1. https://isc.sans.edu/forums/diary/Help+eliminate+unquoted+path+vulnerabilities/14464/
2. https://medium.com/@SumitVerma101/windows-privilege-escalation-part-1-unquoted-service-path-c7a011a8d8ae
3. https://ss64.com/nt/icacls.html

## how to fix:
https://www.commonexploits.com/unquoted-service-paths/
