# enum4Linux 
### for enumerating information from windows machines and Samba systems
```
enum4Linux [options] <IP>
```

### Complete Scan
```
enum4Linux -a <IP>
```

### Retrieves Username List
```
enum4Linux -U <IP>
```

### Retrieves Groups from Local Machine
```
enum4Linux -G <IP>
```

### Retrieves OS Version
```
enum4Linux -o <IP>
```

### Retrieves SMB share Information
```
enum4Linux -S <IP>
```

### Check if host is part of a domain or workgroup
Enum4linux uses rpcclient’s lsaquery command to ask for a host’s Domain SID. If we get a proper SID we can infer that it is part of a domain. If we get the answer S-0-0 we can infer the host is part of a workgroup. This is done by default, so no command line options are required
```
enum4linux <ip-address>
```

### use all options
```
enum4linux -a <ip-address>
```

### Attempt to get the userlist (-U) and OS information (-o) from the target <ip-address>
```
enum4linux -U -o <ip-address>
```

### Obtain a list of usernames (-U)
using authentication (-u) & (-p) assumes you know at least one valid username and password
```
enum4linux.pl -u <username> -p <password> -U <ip-address>
```

### Obtaining a List of Usernames via RID Cycling (RestrictAnonymous = 1)
```
enum4linux.pl -r <ip-address>
```

### You can specify a custom range of RIDs (ie. 500-520) using the -R option. This implies -r, so your don’t have specify the -r option:
```
enum4linux.pl -R 500-520 <ip-address>
```

### Group membership
If the remote host allow it, you can get a list of groups and their members using the -G option 
```
enum4linux.pl -G <ip-address>
```

### Getting nbtstat Information
The -n option causes enum4linux to run nmblookup and does some extra parsing on it’s output to provide human-readable information about the remote host.
```
enum4linux.pl -n <ip-address>
```

### Listing Windows shares
If the server allows it, you can obtain a complete list of shares with the -S option. This uses smbclient under the bonnet which also seems to grab the browse list. Enum4linux will also attempt to connect to each share with the supplied credentials null session usually, but you could use -u user -p pass to use something else. It will report whether it could connect to the share and whether it was possible to get a directory listing.
```
enum4linux.pl -S <ip-address>
```

### Some hosts don’t let your retrieve a share list. 
In these situations, it is still possible to perform a dictionary attack to guess share names. use of the -s option with a dictionary file to guess the names of some shares
```
enum4linux.pl -s /Path/To/WordList.txt <ip-address>
```

### Getting OS information
The -o option gets OS information using smbclient. 
```
enum4linux.pl -o <ip-address>
```

### Printer information
get information about printers known to the remote device with the -i option.
```
enum4linux.pl -i <ip-address>
```


## HELP output
```
enum4linux v0.8.9 (http://labs.portcullis.co.uk/application/enum4linux/)
Copyright (C) 2011 Mark Lowe (mrl@portcullis-security.com)

Simple wrapper around the tools in the samba package to provide similar
functionality to enum.exe (formerly from www.bindview.com).  Some additional
features such as RID cycling have also been added for convenience.

Usage: ./enum4linux.pl [options] ip

Options are (like "enum"):
    -U        get userlist
    -M        get machine list*
    -S        get sharelist
    -P        get password policy information
    -G        get group and member list
    -d        be detailed, applies to -U and -S
    -u user   specify username to use (default "")
    -p pass   specify password to use (default "")

The following options from enum.exe aren't implemented: -L, -N, -D, -f

Additional options:
    -a        Do all simple enumeration (-U -S -G -P -r -o -n -i).
              This opion is enabled if you don't provide any other options.
    -h        Display this help message and exit
    -r        enumerate users via RID cycling
    -R range  RID ranges to enumerate (default: 500-550,1000-1050, implies -r)
    -K n      Keep searching RIDs until n consective RIDs don't correspond to
              a username.  Impies RID range ends at 999999. Useful
          against DCs.
    -l        Get some (limited) info via LDAP 389/TCP (for DCs only)
    -s file   brute force guessing for share names
    -k user   User(s) that exists on remote system (default: administrator,guest,krbtgt,domain admins,root,bin,none)
              Used to get sid with "lookupsid known_username"
              Use commas to try several users: "-k admin,user1,user2"
    -o        Get OS information
    -i        Get printer information
    -w wrkg   Specify workgroup manually (usually found automatically)
    -n        Do an nmblookup (similar to nbtstat)
    -v        Verbose.  Shows full commands being run (net, rpcclient, etc.)

RID cycling should extract a list of users from Windows (or Samba) hosts
which have RestrictAnonymous set to 1 (Windows NT and 2000), or "Network
access: Allow anonymous SID/Name translation" enabled (XP, 2003).

NB: Samba servers often seem to have RIDs in the range 3000-3050.

Dependancy info: You will need to have the samba package installed as this
script is basically just a wrapper around rpcclient, net, nmblookup and
smbclient.  Polenum from http://labs.portcullis.co.uk/application/polenum/
is required to get Password Policy info.
```

