# Simulated Bind Shell Attack

If you want to simulate the attack in this post, you can use the netcat command which opens a TCP port on 31337, but sends all data to /dev/null instead of a real shell. The commands below delete the binary as well after it starts so you can experiment with recovering the deleted process binary.

```bash
cd /tmp
cp /bin/nc /tmp/x7
./x7 -vv -k -w 1 -l 31337 > /dev/null &
rm x7
```

### Suspicious Network Port Spotted
In our example we saw something odd when we ran:

```bash
netstat -nalp
```

netstat shows a process named “x7” PID with a listening port that we don’t recognize.

![Linux Bind Shell Suspicious Port](https://example.com/image.jpg)


### Obtain /proc Listing for Suspicious Process ID
First thing we’ll do is list out Process ID (PID) under /proc/<PID> to see what is going on. Our PID of interest is 5805:

```bash
ls -al /proc/5805
```

Below we see a couple odd things.
1. The current working directory (cwd) is /tmp.
2. The binary was in /tmp, but was deleted.

A lot of exploits work out of /tmp and /dev/shm on Linux. These are both world writable directories on most all Linux systems and many malware and exploits will drop their payloads there to run. A process that is making its home in /tmp or /dev/shm is suspicious.

![Linux Process Forensics /proc Listing](https://example.com/image.jpg)


### Recover Deleted Linux Malware Binary
Before we do anything else, we’ll recover the deleted binary. As long as the process is still running, it is very easy to recover a deleted process binary on Linux:
```bash
cp /proc/<PID>/exe /tmp/recovered_bin
```

![Recovering Deleted Malware Process Binary on Linux](https://example.com/image.jpg)


### Obtain Deleted Linux Malware Hashes
Now that we’ve saved the Linux binary somewhere off the system, we can recover the hashes easily.

If you are using netcat to simulate the attack, you can recover the deleted binary and run a hash on the system netcat command and the recovered binary and see they match.

```bash
sha1sum /bin/nc
<hash here>
sha1sum /tmp/recovered_bin
<identical hash here>
```

![Getting Linux Malware Cryptographic Hash](https://example.com/image.jpg)


### Explore Linux Malware Command Line
The command line is stored under /proc/<PID>/cmdline and the command name is shown under /proc/<PID>/comm.

Some malware will cloak this data to masquerade as another process. You may see different names for the program in this case, or even names that are trying to hide as something else like apache or sshd.

If you see multiple different names, then it is very likely the program is malicious.
```bash
cat /proc/<PID>/comm 
cat /proc/<PID>/cmdline
```

![Getting Linux Malware Command Line](https://example.com/image.jpg)



### Explore Linux Malware Process Environment
Now let’s take a look at the environment our malware inherited when it started. This can often reveal information about who or what started the process. Here we see the process was started with sudo by another user:

```bash
strings /proc/<PID>/environ
```

![Obtaining Linux Malware Process Environment](https://example.com/image.jpg)



### Investigate Linux Malware Open File Descriptors
We’ll now investigate the file descriptors the malware has open. This can often show you hidden files and directories that the malware is using to stash things along with open sockets:

```bash
ls -al /proc/<PID>/fd
```

![Linux Malware Open File Descriptors](https://example.com/image.jpg)



### Investigate Linux Malware Process Maps
Another area to look into is the Linux process maps. This shows libraries the malware is using and again can show links to malicious files it is using as well.

```bash
cat /proc/<PID>/maps
```

![Linux Malware Process Maps](https://example.com/image.jpg)



### Investigate Linux Malware Process Stack
The /proc/<PID>/stack area can sometimes reveal more details. We’ll look at that like this:

```bash
cat /proc/<PID>/stack
```

In this case we see some network accept() calls indicating this is a network server waiting for a connection. Sometimes there won’t be anything obvious here, but sometimes there is. It just depends what the process is doing so it’s best to look.

![Linux Malware Forensics Process Stack](https://example.com/image.jpg)


### Get Linux Malware Status
Finally, let’s look at /proc/<PID>/status for overall process details. This can reveal parent PIDs, etc.

```bash
cat /proc/<PID>/status
```

![Linux Malware /proc Status](https://example.com/image.jpg)





















## References:
1. https://dmfrsecurity.com/2021/02/23/using-procfs-for-forensics-and-incident-response/
2. https://sandflysecurity.com/blog/basic-linux-malware-process-forensics-for-incident-responders/
3. https://github.com/vm32/Linux-Incident-Response
