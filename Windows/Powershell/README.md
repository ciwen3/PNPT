# Powershell Commands
## Discover DHCP Servers:
```
Get-DhcpServerInDC
```
## Get local machine IP info
```
Get-NetIPConfiguration
```
## List Domain Controllers:
```
Get-ADDomainController
```
## List FSMO Rules:
```
# From Scripting Guys Blog
# https://blogs.technet.microsoft.com/heyscriptingguy/2014/11/28/powertip-use-powershell-to-get-list-of-fsmo-role-holders/
Get-ADDomain | Select-Object InfrastructureMaster, RIDMaster, PDCEmulator
Get-ADForest | Select-Object DomainNamingMaster, SchemaMaster
Get-ADDomainController -Filter * |
Select-Object Name, Domain, Forest, OperationMasterRoles |
Where-Object {$_.OperationMasterRoles} |
Format-Table -AutoSize
```



https://github.com/CyberPoint/

glinares

Use Cacls.exe to view and manage Windows ACLs

Weak ACL Permissions:
Rights     : FullControl
FullPath   : C:\ProgramData\NVIDIA Corporation\GeForce Experience\Update\GFExperience.NvStreamSrv\amd64\server\nvinject.dll
Domain     : Everyone
ID         :
AccessType : Allow
PS: Somebody you should probably look into this ;) just saying

Get-Acl | Format-List

Get-Acl -Path * | Format-List

Access: BUILTIN\Administrators Allow  FullControl

Get an ACL for a folder:
Get-Acl C:\Windows


Get an ACL for a folder using wildcards
Get-Acl C:\Windows\s*.log | Format-List -Property PSPath, Sddl


Get count of Audit entries for an ACL
Get-Acl C:\Windows\s*.log -Audit | ForEach-Object { $_.Audit.Count }


Get an ACL for a registry key
Get-Acl -Path HKLM:\System\CurrentControlSet\Control | Format-List


Get an ACL using **InputObject**
Get-Acl -InputObject (Get-StorageSubSystem -Name S087)













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
```
Get-Acl | Format-List
Get-Acl -Path * | Format-List
```
Looking for: 
```
Access: BUILTIN\Administrators Allow  FullControl
```
### Get an ACL for a folder:
```
Get-Acl C:\Windows
```

### Get an ACL for a folder using wildcards
```
Get-Acl C:\Windows\s*.log | Format-List -Property PSPath, Sddl
```

### Get count of Audit entries for an ACL
```
Get-Acl C:\Windows\s*.log -Audit | ForEach-Object { $_.Audit.Count }
```

### Get an ACL for a registry key
```
Get-Acl -Path HKLM:\System\CurrentControlSet\Control | Format-List
```

### Get an ACL using **InputObject**
```
Get-Acl -InputObject (Get-StorageSubSystem -Name S087)
```


















