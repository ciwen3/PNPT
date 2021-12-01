# Winodws Enumeration

## Powershell side note:
Execution Policy Bypass
```
powershell -ep bypass
```
## Check for Linux on Windows:
WSL (windows Subsystem for Linux)

```
C:\Users\tyler\Desktop>where /R C:\windows bash.exe
where /R C:\windows bash.exe
C:\Windows\WinSxS\amd64_microsoft-windows-lxss-bash_31bf3856ad364e35_10.0.17134.1_none_251beae725bc7de5\bash.exe

C:\Users\tyler\Desktop>where /R C:\windows wsl.exe
where /R C:\windows wsl.exe
C:\Windows\WinSxS\amd64_microsoft-windows-lxss-wsl_31bf3856ad364e35_10.0.17134.1_none_686f10b5380a84cf\wsl.exe

C:\Users\tyler\Desktop>
```


## CMD read dll side note:
 ```
 regsvr32 filename. dll
```

## On the machine:
### systeminfo
```
C:\>systeminfo

Host Name:                 DESKTOP-SGM6660
OS Name:                   Microsoft Windows 10 Pro
OS Version:                10.0.18362 N/A Build 18362
OS Manufacturer:           Microsoft Corporation
OS Configuration:          Standalone Workstation
OS Build Type:             Multiprocessor Free
Registered Owner:          john
Registered Organization:   N/A
Product ID:                00330-80210-83619-AA888
Original Install Date:     6/28/2020, 7:02:35 PM
System Boot Time:          10/15/2020, 1:06:04 AM
System Manufacturer:       HP
System Model:              HP ZBook Studio G3
System Type:               x64-based PC
Processor(s):              1 Processor(s) Installed.
                           [01]: Intel64 Family 6 Model 94 Stepping 3 GenuineIntel ~2712 Mhz
BIOS Version:              HP N82 Ver. 01.18, 6/8/2017
Windows Directory:         C:\WINDOWS
System Directory:          C:\WINDOWS\system32
Boot Device:               \Device\HarddiskVolume2
System Locale:             en-us;English (United States)
Input Locale:              en-us;English (United States)
Time Zone:                 (UTC-08:00) Pacific Time (US & Canada)
Total Physical Memory:     32,687 MB
Available Physical Memory: 18,812 MB
Virtual Memory: Max Size:  37,551 MB
Virtual Memory: Available: 19,515 MB
Virtual Memory: In Use:    18,036 MB
Page File Location(s):     C:\pagefile.sys
Domain:                    WORKGROUP
Logon Server:              \\DESKTOP-SGM5QN0
Hotfix(s):                 21 Hotfix(s) Installed.
                           [01]: KB4578974
```

### systeminfo | findstr /B /C:"OS Name" /C:"OS Version" /C:"System Type"
```
C:\>systeminfo | findstr /B /C:"OS Name" /C:"OS Version" /C:"System Type"

OS Name:                   Microsoft Windows 10 Pro
OS Version:                10.0.18362 N/A Build 18362
System Type:               x64-based PC
```

### Network Information: 
```
ipconfig 
```

### Running Services: 
```
tasklist 
```
## List services that use the 
### network functionality module ws2_32.dll
```
C:\Windows\system32> tasklist /m ws2_32.dll	
```
### Configure Windows machine as Access Point:
```
netsh wlan set hostednetwork mode=allow ssid=<my-ssid> key=<my-password> && netsh wlan start hostednetwork	
```
### get a list of TCP & UDP activity every second
```
netstat -naob 1 | find "<ip-address or port>"	
```
### get a list of all available attributes of all running processes
```
wmic process list full	
```
### get a list of services running inside of each process
```
tasklist /svc	# CMD
```






# Windows Management Instrumentation Commandline
## Winodws Updates
### wmic qfe
```
C:\>wmic qfe

Caption                                     CSName           Description      FixComments  HotFixID   InstallDate  InstalledBy          InstalledOn  Name  ServicePackInEffect  Status
http://support.microsoft.com/?kbid=4578974  DESKTOP-SGM5QN0  Update                        KB4578974               NT AUTHORITY\SYSTEM  10/15/2020
http://support.microsoft.com/?kbid=4497165  DESKTOP-SGM5QN0  Update                        KB4497165               NT AUTHORITY\SYSTEM  7/18/2020
http://support.microsoft.com/?kbid=4498523  DESKTOP-SGM5QN0  Security Update               KB4498523               NT AUTHORITY\SYSTEM  6/29/2020
http://support.microsoft.com/?kbid=4506933  DESKTOP-SGM5QN0  Security Update               KB4506933               NT AUTHORITY\SYSTEM  6/29/2020
```


### wmic qfe get Caption,Description,HotFixID,InstalledOn
```
C:\>wmic qfe get Caption,Description,HotFixID,InstalledOn

Caption                                     Description      HotFixID   InstalledOn
http://support.microsoft.com/?kbid=4578974  Update           KB4578974  10/15/2020
http://support.microsoft.com/?kbid=4497165  Update           KB4497165  7/18/2020
http://support.microsoft.com/?kbid=4498523  Security Update  KB4498523  6/29/2020
http://support.microsoft.com/?kbid=4506933  Security Update  KB4506933  6/29/2020
http://support.microsoft.com/?kbid=4508433  Security Update  KB4508433  6/29/2020
```

## drive enumeration
### wmic logicaldisk
```
C:\>wmic logicaldisk

Access  Availability  BlockSize  Caption  Compressed  ConfigManagerErrorCode  ConfigManagerUserConfig  CreationClassName  Description       DeviceID  DriveType  ErrorCleared  ErrorDescription  ErrorMethodology  FileSystem  FreeSpace      InstallDate  LastErrorCode  MaximumComponentLength  MediaType  Name  NumberOfBlocks  PNPDeviceID  PowerManagementCapabilities  PowerManagementSupported  ProviderName  Purpose  QuotasDisabled  QuotasIncomplete  QuotasRebuilding  Size           Status  StatusInfo  SupportsDiskQuotas  SupportsFileBasedCompression  SystemCreationClassName  SystemName       VolumeDirty  VolumeName               VolumeSerialNumber
0                                C:       FALSE                                                        Win32_LogicalDisk  Local Fixed Disk  C:        3                                                            NTFS        57318518784                                255                     12         C:                                                                                                                                                                   250057060352                       FALSE               TRUE                          Win32_ComputerSystem     DESKTOP-SGM5QN0                                        D0219E72
``` 

### wmic logicaldisk get caption,description,providername
```
C:\>wmic logicaldisk get caption,description,providername

Caption  Description       ProviderName
C:       Local Fixed Disk
E:       Local Fixed Disk
F:       Local Fixed Disk
G:       Local Fixed Disk
```

## Next Check Folder Permissions:
### icacls "C:\WINDOWS\system32\AppVClient.exe"
```
C:\>icacls "C:\WINDOWS\system32\AppVClient.exe"

C:\WINDOWS\system32\AppVClient.exe NT SERVICE\TrustedInstaller:(F)
                                   BUILTIN\Administrators:(RX)
                                   NT AUTHORITY\SYSTEM:(RX)
                                   BUILTIN\Users:(RX)
                                   APPLICATION PACKAGE AUTHORITY\ALL APPLICATION PACKAGES:(RX)
                                   APPLICATION PACKAGE AUTHORITY\ALL RESTRICTED APPLICATION PACKAGES:(RX)

Successfully processed 1 files; Failed processing 0 files
```
looking for (WD) or (AD)
- Delete: removes files or DLLs
- Write Data/ Add File: add a DLL that is sideloaded into an application with elevated privileges
- Write Attributes: set file attributes to hidden or system, poenially hiding them from view by most users
- Append Data: allows the user to add data to the end of a file, but not overwrite any existing data
- Change Permissions: this is pretty much full control 


# User Enumeration:
### C:\>whoami 

### C:\>whoami /priv
```
C:\>whoami /priv

PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                          State
============================= ==================================== ========
SeShutdownPrivilege           Shut down the system                 Disabled
SeChangeNotifyPrivilege       Bypass traverse checking             Enabled
SeUndockPrivilege             Remove computer from docking station Disabled
SeIncreaseWorkingSetPrivilege Increase a process working set       Disabled
SeTimeZonePrivilege           Change the time zone                 Disabled
```

## Users on this Machine
### whoami
```
C:\>whoami
desktop-sgm6660\john
```

### whoami /groups
```
C:\>whoami /groups

GROUP INFORMATION
-----------------

Group Name                                                    Type             SID          Attributes
============================================================= ================ ============ ==================================================
Everyone                                                      Well-known group S-1-1-0      Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\Local account and member of Administrators group Well-known group S-1-5-114    Group used for deny only
BUILTIN\Administrators                                        Alias            S-1-5-32-544 Group used for deny only
BUILTIN\Performance Log Users                                 Alias            S-1-5-32-559 Mandatory group, Enabled by default, Enabled group
BUILTIN\Users                                                 Alias            S-1-5-32-545 Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\INTERACTIVE                                      Well-known group S-1-5-4      Mandatory group, Enabled by default, Enabled group
CONSOLE LOGON                                                 Well-known group S-1-2-1      Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\Authenticated Users                              Well-known group S-1-5-11     Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\This Organization                                Well-known group S-1-5-15     Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\Local account                                    Well-known group S-1-5-113    Mandatory group, Enabled by default, Enabled group
LOCAL                                                         Well-known group S-1-2-0      Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\NTLM Authentication                              Well-known group S-1-5-64-10  Mandatory group, Enabled by default, Enabled group
Mandatory Label\Medium Mandatory Level                        Label            S-1-16-8192
```


### net user
```
C:\>net user

User accounts for \\DESKTOP-SGM5QN0

-------------------------------------------------------------------------------
accName                  Administrator            john
DefaultAccount           Guest                    WDAGUtilityAccount
The command completed successfully.
```

### net user john
```
C:\>net user john

User name                    john
Full Name
Comment
User's comment
Country/region code          000 (System Default)
Account active               Yes
Account expires              Never

Password last set            ‎6/‎28/‎2020 7:25:20 PM
Password expires             Never
Password changeable          ‎6/‎28/‎2020 7:25:20 PM
Password required            No
User may change password     Yes

Workstations allowed         All
Logon script
User profile
Home directory
Last logon                   ‎10/‎20/‎2020 8:04:25 AM

Logon hours allowed          All

Local Group Memberships      *Administrators		<== This is what we are looking for. 
Global Group memberships     *None
The command completed successfully.
```

### net localgroup
This doesn't always work, depends on groups being setup. 
```
C:\>net localgroup

Aliases for \\DESKTOP-SGM5QN0

-------------------------------------------------------------------------------
*Access Control Assistance Operators
*Administrators
*Backup Operators
*Cryptographic Operators
*Device Owners
*Distributed COM Users
*Event Log Readers
*Guests
*Hyper-V Administrators
*IIS_IUSRS
*Network Configuration Operators
*Performance Log Users
*Performance Monitor Users
*Power Users
*Remote Desktop Users
*Remote Management Users
*Replicator
*System Managed Accounts Group
*Users
The command completed successfully.
```

If it fails:
```
C:\>net localgroup 
System error 1376 has occurred.

The specified local group does not exist.
```

### net localgroup administrator
```
C:\>net localgroup administrator
```

## Active Connections:
### netstat
```
C:\>netstat

Active Connections

  Proto  Local Address          Foreign Address        State
  TCP    127.0.0.1:5354         DESKTOP-SGM5QN0:49669  ESTABLISHED
  TCP    192.168.1.11:58469     a23-204-248-59:https   CLOSE_WAIT
  TCP    192.168.1.11:59815     52.242.211.89:https    ESTABLISHED
  TCP    192.168.1.11:59853     85:https               ESTABLISHED
  TCP    192.168.1.11:59859     websocket-cs:https     ESTABLISHED
  TCP    192.168.1.11:60198     ec2-52-35-62-75:https  ESTABLISHED
  TCP    192.168.1.11:60207     72.21.81.200:https     CLOSE_WAIT
  TCP    192.168.1.11:60210     a72-247-211-225:https  CLOSE_WAIT
  TCP    192.168.1.11:60215     ec2-52-35-62-75:https  ESTABLISHED
  TCP    192.168.1.11:60250     dns:https              ESTABLISHED
  TCP    192.168.1.11:60267     52.167.253.237:https   TIME_WAIT
  TCP    192.168.1.11:60268     a23-204-249-79:https   ESTABLISHED
  TCP    192.168.1.11:60270     ec2-52-25-212-16:https  CLOSE_WAIT
```

### View Domain Groups
```
net group /domain
```

### View Members of Domain Group
```
net group /domain <Group Name>
```

### net accounts
```
C:\>net accounts
Force user logoff how long after time expires?:       Never
Minimum password age (days):                          0
Maximum password age (days):                          42
Minimum password length:                              0
Length of password history maintained:                None
Lockout threshold:                                    Never
Lockout duration (minutes):                           30
Lockout observation window (minutes):                 30
Computer role:                                        WORKSTATION
The command completed successfully.
```
save output:
```
NET ACCOUNTS /DOMAIN >ACCOUNTS.TXT 
```

### NET CONFIG:
This command will return the server name, version of Windows, active network adapter information/MAC address, Server hidden status, Maximum Logged On Users, Maximum open files per session, Idle session time, and assign it to a file called SERVER.TXT
```
NET CONFIG SERVER >SERVER.TXT 
```

This command will return the workstation name, user name, version of Windows, network adapter, network adapter information/MAC address, Logon domain, COM Open Timeout, COM Send Count, COM Send Timout, and write it to a file called WKST.TXT.
```
NET CONFIG WORKSTATION >WKST.TXT 
```

### net user
Displays a list of all user accounts for the local computer
```
net user 
```
Displays information about the user \<account-name\> 
```
net user <account-name>
net user /domain
```


### Net Group Syntax:
```
net group /domain admins
net group /domain controllers
```
### List Groups
```
net group
```
Adds a group called \<group-name\> to the local user accounts database:
```
net group <group-name> /add
```
Adds the existing user accounts user1, user2, and user3 to the \<group-name\> group on the local computer
```
net group <group-name> user1 user2 user3 /add
```
Adds the existing user accounts user1, user2, and user3 to the \<group-name\> group in the domain database
```
net group <group-name> user1 user2 user3 /add /domain
```
List user of \<group-name\>
```
net group <group-name>
```
Adds a group called \<group-name\> to the domain database 
```
net group <group-name> /add /domain
```

### Net Computer Syntax:
Adds the computer Grizzlybear to the domain database
```
net computer \\grizzlybear /add
```

### Net Localgroup Syntax:
Displays a list of all the local groups on the local server, type:
```
net localgroup
net localgroup administrators
net localgroup admins
net localgroup admin
```

Adds a local group called \<group-name\> to the local user accounts database
```
net localgroup <group-name> /add
```
Adds a local group called \<group-name\> to the domain user accounts database
```
net localgroup <group-name> /add /domain
```
Adds the existing user accounts stevev, ralphr (from the Sales domain), and jennyt to the \<group-name\> local group on the local computer
```
net localgroup \<group-name\> stevev sales\ralphr jennyt /add
```
Adds the existing user accounts stevev, ralphr, and jennyt to the \<group-name\> group of a domain
```
net localgroup <group-name> stevev ralphr jennyt /add /domain
```
Displays users in the \<group-name\> local group
```
net localgroup <group-name>
```
Adds a comment to the \<group-name\> local group record
```
net localgroup <group-name> /comment:"The executive staff."
```


### Net Session Syntax:
Display a list of session information for the local server
```
net session
```
Display session information for a client with the computer name bweston
```
net session \\bweston
```
To end all sessions between the server and the clients connected to it
```
net session /delete
```


### Net Share Syntax:
```
net share <ShareName>
net share <ShareName>=<drive>:<DirectoryPath> [/grant:<user>,{read | change |full}] [/users:<number> | /unlimited] [/remark:<text>] [/cache:{manual | documents | programs | BranchCache |none} ]
net share [/users:<number> | /unlimited] [/remark:<text>] [/cache:{manual | documents | programs | BranchCache |none} ]
net share {<ShareName> | <DeviceName> | <drive>:<DirectoryPath>} /delete
net share <ShareName> \\<ComputerName> /delete
```
Display information about shared resources on the local computer, type:
```
net share       
```
Share a computer's C:\Data directory with the share name DataShare and include a remark, type:
```
net share DataShare=c:\Data /remark:"For department 123."       
```
Stop sharing the DataShare folder you created in the previous example, type:
```
net share DataShare /delete       
```
Share a computer's C:\Art List directory with the share name List, type:
```
net share list="c:\Art List"    
```


### netstat -ano
```
C:\>netstat -ano

Active Connections

  Proto  Local Address          Foreign Address        State           PID
  TCP    0.0.0.0:49668          0.0.0.0:0              LISTENING       3820
  TCP    0.0.0.0:49673          0.0.0.0:0              LISTENING       820
  TCP    127.0.0.1:5354         0.0.0.0:0              LISTENING       4452
  TCP    127.0.0.1:5354         127.0.0.1:49669        ESTABLISHED     4452
  TCP    127.0.0.1:5354         127.0.0.1:49672        ESTABLISHED     4452
  TCP    127.0.0.1:27015        0.0.0.0:0              LISTENING       4536
  TCP    127.0.0.1:49669        127.0.0.1:5354         ESTABLISHED     4536
  TCP    127.0.0.1:49672        127.0.0.1:5354         ESTABLISHED     4536
  TCP    172.28.128.1:139       0.0.0.0:0              LISTENING       4
  TCP    192.168.1.11:139       0.0.0.0:0              LISTENING       4
  TCP    192.168.1.11:58469     23.204.248.59:443      CLOSE_WAIT      9284
  TCP    192.168.1.11:59815     52.242.211.89:443      ESTABLISHED     4576
  TCP    192.168.1.11:60074     35.170.0.145:443       ESTABLISHED     11764
  TCP    192.168.1.11:60207     72.21.81.200:443       CLOSE_WAIT      9852
  TCP    192.168.1.11:60210     72.247.211.225:443     CLOSE_WAIT      9852
  TCP    192.168.1.11:60276     34.210.64.46:443       ESTABLISHED     11764
  TCP    192.168.1.11:60312     8.8.8.8:443            ESTABLISHED     11764
  TCP    192.168.1.11:60313     172.217.14.99:443      TIME_WAIT       0
  TCP    192.168.1.11:60315     23.13.220.177:443      ESTABLISHED     11764
```

### IP Connections
### ipconfig /all
```
C:\Users\c>ipconfig /all

Windows IP Configuration

   Host Name . . . . . . . . . . . . : DESKTOP-SGM5QN0
   Primary Dns Suffix  . . . . . . . :
   Node Type . . . . . . . . . . . . : Hybrid
   IP Routing Enabled. . . . . . . . : No
   WINS Proxy Enabled. . . . . . . . : No

Ethernet adapter Ethernet:

   Media State . . . . . . . . . . . : Media disconnected
   Connection-specific DNS Suffix  . :
   Description . . . . . . . . . . . : Intel(R) Ethernet Connection (2) I219-LM
   Physical Address. . . . . . . . . : 48-BA-4E-00-00-00
   DHCP Enabled. . . . . . . . . . . : Yes
   Autoconfiguration Enabled . . . . : Yes

Wireless LAN adapter Wi-Fi:

   Connection-specific DNS Suffix  . :
   Description . . . . . . . . . . . : Intel(R) Dual Band Wireless-AC 8260
   Physical Address. . . . . . . . . : CC-2F-71-00-00-00
   DHCP Enabled. . . . . . . . . . . : Yes
   Autoconfiguration Enabled . . . . : Yes
   Link-local IPv6 Address . . . . . : fe80::34b1:9ff3:f4cc:dfcc%10(Preferred)
   IPv4 Address. . . . . . . . . . . : 192.168.1.11(Preferred)
   Subnet Mask . . . . . . . . . . . : 255.255.255.0
   Lease Obtained. . . . . . . . . . : Thursday, October 15, 2020 1:06:14 AM
   Lease Expires . . . . . . . . . . : Wednesday, October 21, 2020 7:51:58 AM
   Default Gateway . . . . . . . . . : 192.168.1.1
   DHCP Server . . . . . . . . . . . : 192.168.1.1
   DHCPv6 IAID . . . . . . . . . . . : 130822001
   DHCPv6 Client DUID. . . . . . . . : 00-01-00-01-26-8B-09-06-48-BA-4E-E9-77-7E
   DNS Servers . . . . . . . . . . . : 8.8.8.8
                                       8.8.4.4
   NetBIOS over Tcpip. . . . . . . . : Enabled
```

### ARP Table
### arp -a
```
C:\>arp -a

Interface: 192.168.56.1 --- 0x5
  Internet Address      Physical Address      Type
  192.168.56.255        ff-ff-ff-ff-ff-ff     static
  224.0.0.22            01-00-5e-00-00-16     static
  224.0.0.251           01-00-5e-00-00-fb     static
  224.0.0.252           01-00-5e-00-00-fc     static
  239.255.255.250       01-00-5e-7f-ff-fa     static

Interface: 192.168.1.11 --- 0xa
  Internet Address      Physical Address      Type
  192.168.1.1           3c-37-86-1f-30-23     dynamic
  192.168.1.15          b0-0c-d1-b4-ad-45     dynamic
  192.168.1.255         ff-ff-ff-ff-ff-ff     static
  224.0.0.22            01-00-5e-00-00-16     static
  224.0.0.251           01-00-5e-00-00-fb     static
  224.0.0.252           01-00-5e-00-00-fc     static
  239.255.255.250       01-00-5e-7f-ff-fa     static
  255.255.255.255       ff-ff-ff-ff-ff-ff     static

Interface: 192.168.6.1 --- 0x13
  Internet Address      Physical Address      Type
  192.168.6.255         ff-ff-ff-ff-ff-ff     static
  224.0.0.22            01-00-5e-00-00-16     static
  224.0.0.251           01-00-5e-00-00-fb     static
  224.0.0.252           01-00-5e-00-00-fc     static
  239.255.255.250       01-00-5e-7f-ff-fa     static

Interface: 172.28.128.1 --- 0x16
  Internet Address      Physical Address      Type
  172.28.128.255        ff-ff-ff-ff-ff-ff     static
  224.0.0.22            01-00-5e-00-00-16     static
  224.0.0.251           01-00-5e-00-00-fb     static
  224.0.0.252           01-00-5e-00-00-fc     static
  239.255.255.250       01-00-5e-7f-ff-fa     static
```

### route print
```
C:\>route print
===========================================================================
Interface List
 20...48 ba 4e e9 77 7e ......Intel(R) Ethernet Connection (2) I219-LM
 13...b4 b6 86 90 53 09 ......Broadcom NetXtreme Gigabit Ethernet
 17...ce 2f 71 3a ce 3d ......Microsoft Wi-Fi Direct Virtual Adapter #2
 10...cc 2f 71 3a ce 3d ......Intel(R) Dual Band Wireless-AC 8260
  7...cc 2f 71 3a ce 41 ......Bluetooth Device (Personal Area Network)
  1...........................Software Loopback Interface 1
===========================================================================

IPv4 Route Table
===========================================================================
Active Routes:
Network Destination        Netmask          Gateway       Interface  Metric
          0.0.0.0          0.0.0.0      192.168.1.1     192.168.1.11     50
        127.0.0.0        255.0.0.0         On-link         127.0.0.1    331
        127.0.0.1  255.255.255.255         On-link         127.0.0.1    331
  127.255.255.255  255.255.255.255         On-link         127.0.0.1    331
  255.255.255.255  255.255.255.255         On-link       192.168.6.1    281
  255.255.255.255  255.255.255.255         On-link      192.168.1.11    306
===========================================================================
Persistent Routes:
  None

IPv6 Route Table
===========================================================================
Active Routes:
 If Metric Network Destination      Gateway
  1    331 ::1/128                  On-link
  5    281 fe80::/64                On-link
 22    281 fe80::/64                On-link
 19    281 fe80::/64                On-link
 10    306 fe80::/64                On-link
 10    306 fe80::34b1:9ff3:f4cc:dfcc/128
                                    On-link
 19    281 fe80::bdcd:e4bd:6051:a3a2/128
                                    On-link
  5    281 fe80::dd49:3d5f:3df5:8321/128
                                    On-link
 22    281 fe80::f828:6d11:5d98:5403/128
                                    On-link
  1    331 ff00::/8                 On-link
  5    281 ff00::/8                 On-link
 22    281 ff00::/8                 On-link
 19    281 ff00::/8                 On-link
 10    306 ff00::/8                 On-link
===========================================================================
Persistent Routes:
  None
```

## Firewall

### netsh firewall show state
```
C:\>netsh firewall show state

Firewall status:
-------------------------------------------------------------------
Profile                           = Standard
Operational mode                  = Enable
Exception mode                    = Enable
Multicast/broadcast response mode = Enable
Notification mode                 = Enable
Group policy version              = Windows Defender Firewall
Remote admin mode                 = Disable

Ports currently open on all network interfaces:
Port   Protocol  Version  Program
-------------------------------------------------------------------
No ports are currently open on all network interfaces.

IMPORTANT: Command executed successfully.
However, "netsh firewall" is deprecated;
use "netsh advfirewall firewall" instead.
For more information on using "netsh advfirewall firewall" commands
instead of "netsh firewall", see KB article 947709
at https://go.microsoft.com/fwlink/?linkid=121488 .
```

### netsh firewall show config
```
C:\>netsh firewall show config

Domain profile configuration:
-------------------------------------------------------------------
Operational mode                  = Enable
Exception mode                    = Enable
Multicast/broadcast response mode = Enable
Notification mode                 = Enable

Allowed programs configuration for Domain profile:
Mode     Traffic direction    Name / Program
-------------------------------------------------------------------

Port configuration for Domain profile:
Port   Protocol  Mode    Traffic direction     Name
-------------------------------------------------------------------

Standard profile configuration (current):
-------------------------------------------------------------------
Operational mode                  = Enable
Exception mode                    = Enable
Multicast/broadcast response mode = Enable
Notification mode                 = Enable

Service configuration for Standard profile:
Mode     Customized  Name
-------------------------------------------------------------------
Enable   No          Network Discovery

Allowed programs configuration for Standard profile:
Mode     Traffic direction    Name / Program
-------------------------------------------------------------------
Enable   Inbound              Nmap / C:\program files (x86)\nmap\nmap.exe
Enable   Inbound              teams.exe / C:\users\john\appdata\local\microsoft\teams\current\teams.exe
Enable   Inbound              VirtualBox Manager / C:\program files\oracle\virtualbox\virtualboxvm.exe
Enable   Inbound              miner.exe / C:\users\c\appdata\local\programs\nicehash miner\miner_plugins\e7a58030-94eb-11ea-a64d-17be303ea466\bins\13.2\miner.exe
Enable   Inbound              Java(TM) Platform SE binary / C:\program files (x86)\arduino\java\bin\javaw.exe
Enable   Inbound              phoenixminer.exe / C:\users\john\appdata\local\programs\nicehash miner\miner_plugins\fa369d10-94eb-11ea-a64d-17be303ea466\bins\11.2\phoenixminer_5.0e_windows\phoenixminer.exe
Enable   Inbound              vboxheadless / C:\program files\oracle\virtualbox\vboxheadless.exe
Enable   Inbound              code.exe / C:\users\john\appdata\local\programs\microsoft vs code\code.exe
Enable   Inbound              Firefox (C:\Program Files\Mozilla Firefox) / C:\Program Files\Mozilla Firefox\firefox.exe

Port configuration for Standard profile:
Port   Protocol  Mode    Traffic direction     Name
-------------------------------------------------------------------

Log configuration:
-------------------------------------------------------------------
File location   = C:\WINDOWS\system32\LogFiles\Firewall\pfirewall.log
Max file size   = 4096 KB
Dropped packets = Disable
Connections     = Disable

IMPORTANT: Command executed successfully.
However, "netsh firewall" is deprecated;
use "netsh advfirewall firewall" instead.
For more information on using "netsh advfirewall firewall" commands
instead of "netsh firewall", see KB article 947709
at https://go.microsoft.com/fwlink/?linkid=121488 .
```

# Powershell:
## Get Firewall Rules
```
Get-NetFirewallRule -all | Out-GridView		
Get-NetFirewallRule -all | Export-csv <file_path.csv>	
```

## Add Firewall Rule
```
New-NetFirewallRule -Action Allow -DisplayName Pentester-C2 -RemoteAddress <ip-address>		
```

## Find Juicy Stuff:
#### search folder path\to\directory for files that contain the "STRING"
```
ls -r c:\path\to\directory -file | % {Select-String -path $_ -pattern STRING}	
```

## Running Services: 
```
get-process
```

## Older Windows versions will use:
```
netsh advfirewall firewall dump 
```

## Service Control

### sc query windefend
Use Service Control to query if Winodws Defender Anti Virus is running
```
C:\>sc query windefend

SERVICE_NAME: windefend
        TYPE               : 10  WIN32_OWN_PROCESS
        STATE              : 4  RUNNING
                                (STOPPABLE, NOT_PAUSABLE, ACCEPTS_SHUTDOWN)
        WIN32_EXIT_CODE    : 0  (0x0)
        SERVICE_EXIT_CODE  : 0  (0x0)
        CHECKPOINT         : 0x0
        WAIT_HINT          : 0x0
```

### sc queryex type= service
Use Service Control to query what services are running. long list given. 
```
C:\>sc queryex type= service

SERVICE_NAME: WpnUserService_9a12b
DISPLAY_NAME: Windows Push Notifications User Service_9a12b
        TYPE               : f0   ERROR
        STATE              : 4  RUNNING
                                (STOPPABLE, NOT_PAUSABLE, ACCEPTS_PRESHUTDOWN)
        WIN32_EXIT_CODE    : 0  (0x0)
        SERVICE_EXIT_CODE  : 0  (0x0)
        CHECKPOINT         : 0x0
        WAIT_HINT          : 0x0
        PID                : 6864
        FLAGS              :
```

## Scheduled Tasks
### schtasks /query /fo LIST /v

```
C:\>schtasks /query /fo LIST /v

Folder: \Mozilla
HostName:                             DESKTOP-SGM6660
TaskName:                             \Mozilla\Firefox Default Browser Agent 308046B0AF4A39CB
Next Run Time:                        10/20/2020 6:53:15 PM
Status:                               Ready
Logon Mode:                           Interactive only
Last Run Time:                        10/19/2020 6:53:16 PM
Last Result:                          0
Author:                               Mozilla
Task To Run:                          C:\Program Files\Mozilla Firefox\default-browser-agent.exe do-task "308046B0AF4A39CB"
Start In:                             N/A
Comment:                              The Default Browser Agent task checks when the default changes from Firefox to another browser. If the change happens under suspicious circumstances, it will prompt users to change back to Firefox no more than two times. This task is installed automatic
Scheduled Task State:                 Enabled
Idle Time:                            Disabled
Power Management:
Run As User:                          DESKTOP-SGM6660\john
Delete Task If Not Rescheduled:       Disabled
Stop Task If Runs X Hours and X Mins: 00:35:00
Schedule:                             Scheduling data is not available in this format.
Schedule Type:                        Daily
Start Time:                           6:53:15 PM
Start Date:                           10/14/2020
End Date:                             N/A
Days:                                 Every 1 day(s)
Months:                               N/A
Repeat: Every:                        Disabled
Repeat: Until: Time:                  Disabled
Repeat: Until: Duration:              Disabled
Repeat: Stop If Still Running:        Disabled
```

### Sorting it on Linux:
Keep in mind you can of course change the name SYSTEM to another privileged user.
```
cat schtask.txt | grep "SYSTEM\|Task To Run" | grep -B 1 SYSTEM
```


# PowerShell Commands:
## ping sweeper:
```
1..255 | % {echo "10.10.10.$_"; ping -n 1 -w 100 10.10.10.$_ | Select-String ttl}	
```

## Port Scanner:
```
1..1024 | % {echo ((new-object Net.Sockets.TcpClient).Connect("<ip-address>",$_)) "Port $_ is open!"} 2>$null	
```
