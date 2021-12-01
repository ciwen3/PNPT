# Commands:
check to see what sudo privledges the user has
```
sudo -l
cat /etc/sudoers
```

# other Super Users?:
```
grep -v -E "^#" /etc/passwd | awk -F: '$3 == 0 {print $1}'
```

# Alias
### show list of alias commands avalable
```
alias
```
### create alias
```
alias ll='ls -al'
```
add to ~/.bashrc or ~/.bash_aliases

### remove aliases
```
unalias {NAME}
```
### remove all aliases
```
unalias -a
```

# user discovery
```
whoami
groups
id
pwd
who 
w
last
```

# shell discovery 
this will print out what shell you are using. 
```
ls -l /proc/$$/exe
```

# Finger
### use finger to see logged in user info
```
finger -s

Login     	Name       	Tty      Idle   Login Time   Office     Office Phone
<login-name> 	<user-name>    	tty7     13:53  Apr 25 12:37 (:0)
```
### use finger to see logged in user extra info
```
finger -l
Login: <login-name>     		Name: <user-name>
Directory: /home/mygu               	Shell: /bin/bash
On since Sat Apr 25 12:37 (PDT) on tty7 from :0
   13 hours 54 minutes idle
No mail.
No Plan.
```
### Finger users on a Specific IP
```
finger @TARGET-IP
```
### Finger a Specific Username
```
finger batman@TARGET-IP 
```
### Solaris bug that shows all logged in users:
```
finger 0@host  
```

# search
```
whereis (locate installed binaries on the system)
locate (find files within the system)
find 
```
# find file with name containing "file-name-filter", then search that file for specific "string"
```
find /path/to/directory -name "file-name-filter" -type f -exec grep -i "string" {} \; -print 2>/dev/null
```

# users and password hashes
```
cat /etc/passwd
cat /etc/shadow
```

# User History
```
history
cat ~/.bash_history
cat ~/.nano_history
cat ~/.atftp_history
cat ~/.mysql_history
cat ~/.php_history
```

# Machine discovery
```
uname -a
lsb_release -a
cat /etc/os-release
env
```

# Network configuration 
```
/sbin/ifconfig -a
iwconfig
ip addr
cat /etc/network/interfaces
cat /etc/sysconfig/network
cat /etc/resolv.conf
cat /etc/sysconfig/network
cat /etc/networks
iptables -L
hostname
dnsdomainname
netstat -antup
lsof -i
```

# Public IP address
```
curl -4 icanhazip.com
dig +short myip.opendns.com @resolver1.opendns.com
wget -qO- ifconfig.me/ip
```
# lists available exploits Linux kernel in kali Linux
```
searchsploit Linux Kernel 2.6.24 
```



# Linux files to cat:
```
.rhosts (allows remote logins)
~/.ssh/authorized_keys
~/.ansible.cfg
/etc/ansible/ansible.cfg (ansible config file)
/etc/ansible/hosts (list of ansible hosts)
/etc/apache2/ 
/etc/apache2/apache2.conf
/etc/apache2/conf/httpd.conf (Apache configuration file)
/etc/apache2/conf/sites-enabled/ (enabled Apache virtual hosts)
/etc/chttp.conf
/etc/cloud/cloud.cfg
/etc/ (configuration files)
/etc/crontab
/etc/cups/cupsd.conf
/etc/fstab
/etc/group (user groups)
/etc/host.conf
/etc/hosts
/etc/hosts (IP addresses of the specified hosts)
/etc/httpd/conf/httpd.conf
/etc/httpd/ (web server settings)
/etc/inetd.conf
inetd files (which can be used to start other network daemons)
/etc/init.d (all the startup scripts)
inittab  (initialization sequence)
/etc/lighttpd.conf
/etc/machine-id
/etc/mtab (dynamic file system information)
/etc/my.cnf.d/client.cnf (MySQL/MariaDB client configuration)
/etc/my.cnf.d/ (MySQL/MariaDB configurations are actually located)
/etc/my.cnf.d/server.cnf - MySQL/MariaDB server configuration
/etc/my.cnf (MySQL/MariaDB link to /etc/my.cnf.d)
/etc/my.conf
/etc/os-release
/etc/passwd (contains the user names)
/etc/php/php.ini (main PHP configuration file)
/etc/profile 
/etc/protocols (list of IP protocols)
/etc/resolv.conf (DNS)
/etc/services (port names for network services)
/etc/shadow (contains the hashed passwords)
/etc/ssh/ (configuration files and SSH keys)
/etc/ssh/ssh_config (SSH client configuration file)
/etc/ssh/sshd_config (SSH server configuration file)
/etc/ssh/ssh_host_dsa_key
/etc/ssh/ssh_host_dsa_key.pub
/etc/ssh/ssh_host_* (other formats)
/etc/syslog.conf
/etc/systemd/ (directory with Systemd files)
/etc/systemd/resolved.conf
/opt/lampp/etc/httpd.conf
/proc/cmdline (Kernel command line information)
/proc/console (Information about current consoles including tty)
/proc/cpuinfo
/proc/devices (Device drivers currently configured for the running kernel)
/proc/dma (Info about current DMA channels)
/proc/fb (Framebuffer devices)
/proc/filesystems (Current filesystems supported by the kernel)
/proc/iomem (Current system memory map for devices)
/proc/ioports (Registered port regions for input output communication with device)
/proc/keys
/proc/key-users
/proc/loadavg (System load average)
/proc/locks (Files currently locked by kernel)
/proc/meminfo (Info about system memory)
/proc/misc (Miscellaneous drivers registered for miscellaneous major device)
/proc/modules (Currently loaded kernel modules)
/proc/mounts (List of all mounts in use by system)
/proc/net/fib_trie (IPv4 info)
/proc/net/if_inet6 (IPv6 info)
/proc/net/route
/proc/net/snmp
/proc/net/tcp (3500007F translates to 127.0.0.53)
/proc/net/unix (running processes)
/proc/partitions (Detailed info about partitions available to the system)
/proc/pci (Information about every PCI device)
/proc/stat (Record or various statistics kept from last reboot)
/proc/swap (Information about swap space)
/proc/uptime (Uptime information in seconds)
/proc/version (Kernel version, gcc version, and Linux distribution installed)
/proc/ (Virtual File System containing info about processes and other system information)
/proc/vmstat
/run (Information about the system since it was loaded)
/tmp
/var/log/apache2/ (Apache web server logs)
/var/log/ (directory contains the logs of various programs and services)
/var/log/httpd/ (Apache web server logs)
/var/log/wtmp  (login log files)
```


