# nmap:
```
-O OS detection
-A Aggressive (active detection)
-p port ports, port - range
```

## Update Script Database: 
```
nmap --script-updatedb
```

## NMAP Scripts:
```
nmap --script vulners
nmap --script vulns
```

## scan: -s

P  ping
V  version
S  syn scan
U  udp scan


## speed: -T\#
```
1 - 1 every 15 sec
2
3
4 - aggressive scan
5 - as fast as possible
```

## Disable:
```
-Pn Disable ping check
-n  Disable DNS lookup
```


## First run 
```
mkdir nmap
sudo nmap -sC -sV -oA nmap/<file-name> <ip-address>
sudo nmap -p- -v -oA nmap/<file-name>-allports <ip-address>

```


## Nmap Basic Commands
```
COMMAND						DESCRIPTION
nmap -sS target					SYN scan 
nmap -sT target					TCP scan
nmap -sU target					UDP scan
nmap -sC target					equivalent to --script=default
nmap -sV target					Service Version Detection
nmap -sO target					look for open ports
nmap -O target					Passive OS Detection requires -sV flag set
nmap -A target					Acitve OS Detection requires -sV flag set
nmap -sI target					IDLE (Zombie) scan
nmap -sA target					ACK scan used to map out firewall rulesets, determining whether they are stateful or not
nmap -v -sS -A -T4 target			Nmap verbose scan, runs syn stealth, T4 timing (should be ok on LAN), OS and service version info, traceroute and scripts against services
nmap -v -sS -p--A -T4 target			As above but scans all TCP ports (takes a lot longer)
nmap -v -sU -sS -p- -A -T4 target		As above but scans all TCP ports and UDP scan (takes even longer)
nmap -v -p 445 --script=smb-check-vulns	--script-args=unsafe=1 192.168.1.X	Nmap script to scan for vulnerable SMB servers - WARNING: unsafe=1 may cause knockover
nmap -vv -Pn -A -sC -sS -T 4 -p- 10.0.0.1                                   Verbose, syn, all ports, all scripts, no ping
nmap -v -sS -A -T4 x.x.x.x                                                  Verbose, SYN Stealth, Version info, and scripts against services.
nmap –script smb-check-vulns.nse –script-args=unsafe=1 -p445 [host]         Nmap script to scan for vulnerable SMB servers – WARNING: unsafe=1 may cause knockover
nmap –script ftp-anon,ftp-bounce,ftp-libopie,ftp-proftpd-backdoor,ftp-vsftpd-backdoor,ftp-vuln-cve2010-4221,tftp-enum -p 21 10.0.0.1        FTP Enumeration
nmap –script smtp-commands,smtp-enum-users,smtp-vuln-cve2010-4344,smtp-vuln-cve2011-1720,smtp-vuln-cve2011-1764 -p 25 10.0.0.1              SMTP Enumeration
nmap -p U:445,T:445 target			UDP and TCP scan on port 445
nmap -T4 -p 53 --script dns-brute <website>	attempt to enumerate DNS hostnames by brute forcing popular subdomain names
```

## Nmap UDP Scanning
```
nmap -sU TARGET
```

### Search nmap scripts for keyword ftp
```
ls /usr/share/nmap/scripts/* | grep ftp		
```

## use nmap to check for vulnerabilities
```
namp --script vuln <ip address>
```

## Nmap UDP Scanning
```
nmap -sU TARGET 
```

## Idenitfy SNMPv3 servers with nmap:
```
nmap -sV -p 161 --script=snmp-info TARGET-SUBNET
```

## Find open SMB Shares
```
nmap -T4 -v -oA shares --script smb-enum-shares --script-args smbuser=username,smbpass=password -p445 192.168.1.0/24   
```

## Enumerate SMB Users
```
nmap -sU -sS --script=smb-enum-users -p U:137,T:139 192.168.11.200-254 
```

## Fingerprint oracle tns:
```
nmap --script=oracle-tns-version 
```

# Oracle:
## Brute force oracle user accounts
## Identify default Oracle accounts:
```
nmap --script=oracle-sid-brute 
nmap --script=oracle-brute 
```
## Run nmap scripts against Oracle TNS:
```
nmap -p 1521 -A TARGET
```
## SQL:
```
nmap -sU --script=ms-sql-info 192.168.1.108 192.168.1.156
```
## NMAP PPTP Fingerprint:
```
nmap –Pn -sV -p 1723 TARGET(S)
```
