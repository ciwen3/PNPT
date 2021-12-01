# Drivers signed by Microsoft
Drivers signed by Microsoft that will allow you to choose the location of the install or print the EULA and give you the ability to open a terminal with full admin access to the PC. 

https://twitter.com/wdormann/status/1432703702079508480
1. click Print 
2. Save as XPS printer 
3. This opens file select prompt, right click cmd.exe  
4. click open 
5. type: 
``` 
whoami 
whoami /priv
whoami /all
```

## File Installation Location Vulnerability
https://twitter.com/UK_Daniel_Card/status/1430428077792940032
1. Plug a Razer mouse (or the dongle)
2. Windows Update will download and execute RazerInstaller as SYSTEM
3. Abuse elevated Explorer to open Powershell with Shift+Right click


### Note: CMD and Powershell locations
1. C:\Windows\System32 folder\cmd.exe
2. C:\Windows\System32\WindowsPowerShell\v1.0\
3. C:\Windows\SysWOW64\WindowsPowerShell\v1.0\







