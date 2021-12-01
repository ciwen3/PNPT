# IP can be encoded in Hex, Decimal, Octal & Binary
https://ncalculators.com/digital-computation/ip-address-hex-decimal-binary.htm

https://www.browserling.com/tools/ip-to-oct

## Example:
```
IP = 192.168.1.1
Hex = C0A80101
Decimal = 3232235777
Binary = 11000000101010000000000100000001
Octal = 0300.0250.0001.0001 
Octal= 030052000401

HEX:
C:\Users\strat0m>ping 0xC0A80101
Pinging 192.168.1.1 with 32 bytes of data:
Reply from 192.168.1.1: bytes=32 time=1ms TTL=64
Reply from 192.168.1.1: bytes=32 time=1ms TTL=64
Reply from 192.168.1.1: bytes=32 time=7ms TTL=64
Reply from 192.168.1.1: bytes=32 time=3ms TTL=64

Ping statistics for 192.168.1.1:
    Packets: Sent = 4, Received = 4, Lost = 0 (0% loss),
Approximate round trip times in milli-seconds:
    Minimum = 1ms, Maximum = 7ms, Average = 3ms

Decimal:
C:\Users\strat0m>ping 3232235777
Pinging 192.168.1.1 with 32 bytes of data:
Reply from 192.168.1.1: bytes=32 time=1ms TTL=64
Reply from 192.168.1.1: bytes=32 time=1ms TTL=64
Reply from 192.168.1.1: bytes=32 time=4ms TTL=64
Reply from 192.168.1.1: bytes=32 time=1ms TTL=64

Ping statistics for 192.168.1.1:
    Packets: Sent = 4, Received = 4, Lost = 0 (0% loss),
Approximate round trip times in milli-seconds:
    Minimum = 1ms, Maximum = 4ms, Average = 1ms

Octal:
C:\Users\strat0m>ping 0300.0250.0001.0001
Pinging 192.168.1.1 with 32 bytes of data:
Reply from 192.168.1.1: bytes=32 time=22ms TTL=64
Reply from 192.168.1.1: bytes=32 time=2ms TTL=64
Reply from 192.168.1.1: bytes=32 time=31ms TTL=64
Reply from 192.168.1.1: bytes=32 time=8ms TTL=64

Ping statistics for 192.168.1.1:
    Packets: Sent = 4, Received = 4, Lost = 0 (0% loss),
Approximate round trip times in milli-seconds:
    Minimum = 2ms, Maximum = 31ms, Average = 15ms
    
Octal:
C:\Users\strat0m>ping 030052000401
Pinging 192.168.1.1 with 32 bytes of data:
Reply from 192.168.1.1: bytes=32 time=1ms TTL=64
Reply from 192.168.1.1: bytes=32 time=4ms TTL=64
Reply from 192.168.1.1: bytes=32 time=1ms TTL=64

Ping statistics for 192.168.1.1:
    Packets: Sent = 3, Received = 3, Lost = 0 (0% loss),
Approximate round trip times in milli-seconds:
    Minimum = 1ms, Maximum = 4ms, Average = 2ms
```
## skipping digits and dots
```
$ ping 4.8
PING 4.8 (4.0.0.8): 56 data bytes
64 bytes from 4.0.0.8: icmp_seq=0 ttl=48 time=156.139 ms
```

# IPLIB
https://github.com/alberanid/python-iplib

Install:
```
┌──(kali㉿kali)-[~]
└─$ pip install iplib
Collecting iplib
  Downloading iplib-1.2.1-py3-none-any.whl (11 kB)
Installing collected packages: iplib
Successfully installed iplib-1.2.1
```

Reference:
```
The following strings can be used instead of constants:
    'binary', 'bin': IP_BIN/NM_BIN
    'octal', 'oct': IP_OCT/NM_OCT
    'decimal', 'dec': IP_DEC/NM_DEC
    'bits', 'bit', 'cidr': NM_BITS
    'wildcard bits', 'wildcard': NM_WILDCARD
    'unknown', 'unk': IP_UNKNOWN/NM_UNKNOWN
```
Use cases:
```
┌──(kali㉿kali)-[~]
└─$ python3       
Python 3.9.1 (default, Dec  8 2020, 07:51:42) 
[GCC 10.2.0] on linux
Type "help", "copyright", "credits" or "license" for more information.
>>> import iplib
>>> iplib.convert('192.168.1.1', notation=iplib.IP_HEX)
'0xc0a80101'
>>> iplib.convert('192.168.1.1', 'hex')
'0xc0a80101'
>>> iplib.convert('192.168.1.1', 'decimal')
'3232235777'
>>> iplib.convert('192.168.1.1', 'dec')
'3232235777'
>>> iplib.convert('192.168.1.1', 'oct')
'0o30052000401'
>>> iplib.convert('192.168.1.1', 'octal')
'0o30052000401'
```
