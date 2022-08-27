# System Enumeration: 
```cmd
systeminfo
systeminfo | findstr /B /C:"OS Name" /C:"OS Version" /C:"System Type"
hostname
wmic qfe
wmic qfe get Caption,Description,HotFixID,InstalledOn
wmic logicaldisk get caption,description,providername

```

# User Enumeration:
```cmd
whoami
whoami /priv
whoami /groups
net user
net user <user-name>
net localgroup

```

# Network Enumeration: ;
```cmd
ipconfig 
ipconfig /all
arp -a        # check "Internet Address" connections
route print
netstat -ano  # check for possible port forwarding exploits for internal only listening ports

```

# Password Hunting: 
https://docs.microsoft.com/en-us/windows-server/administration/windows-commands/findstr
```cmd
findstr /si password *.txt *.ini *.config *.xml
findstr /spin "password" *.*
dir /s *pass* == *cred* == *vnc* == *.config*
```
https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Windows%20-%20Privilege%20Escalation.md#eop---looting-for-passwords

## common files:
```cmd
c:\sysprep.inf
c:\sysprep\sysprep.xml
c:\unattend.xml
%WINDIR%\Panther\Unattend\Unattended.xml
%WINDIR%\Panther\Unattended.xml

```
## Command search for files:
```cmd
dir c:\*vnc.ini /s /b
dir c:\ /s /b | findstr /si *vnc.ini

```
# AV Enumeration:
```cmd
sc query windefend
sc query | findstr /i "virus"
wmic service get Name,Displayname | findstr /i virus

```

## Example: 
```
C:\Users\bob>wmic service get Name,Displayname | findstr /i virus
Microsoft Defender Antivirus Network Inspection Service                             WdNisSvc
Microsoft Defender Antivirus Service                                                WinDefend
```
### Disable firewall
```cmd
sc stop WinDefend
```
```powershell
Set-MpPreference -DisableRealtimeMonitoring $true
```

# Firewall Enumeration:
```cmd
netsh advfirewall firewall dump
netsh firewall show state

```


# Tools: 

