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







