# Practical Network Penetration Tester Certification (PNPT)
Originally for the OSCP. Now for the PNPT certification test. for a lot of reasons including cost, ability to retest for free, and lack of software restrictions. 

https://certifications.tcm-sec.com/pnpt/

# ABOUT THE PNPT EXAM
The PNPT certification exam is a one-of-a-kind ethical hacking certification exam that assesses a student’s ability to perform an external and internal network penetration test at a professional level.  Students will have five (5) full days to complete the assessment and an additional two (2) days to write a professional report.

### In order to receive the certification, a student must:
1. Perform Open-Source Intelligence (OSINT) to gather intel on how to properly attack the network
2. Leverage their Active Directory exploitation skillsets to perform A/V and egress bypassing, lateral and vertical network movements, and ultimately compromise the exam Domain Controller
3. Provide a detailed, professionally written report
4. Perform a live 15-minute report debrief in front of our assessors, comprised of all senior penetration testers

The standalone exam is perfect for students who are already well-versed in OSINT, external penetration testing techniques (such as vulnerability scanning, information gathering, password spraying, credential stuffing, and exploitation), and internal penetration testing techniques (such as LLMNR Poisoning, NTLM Relay Attacks, Kerberoasting, IPv6 attacks, and more).

### Does my exam voucher expire?
No, exam vouchers do not expire.

### Does the certification expire?
No, once acquired, the certification is lifetime.

### Does my training expire?
No, you will have access to your training for life.

### Will I receive a digital certification?
Yes! You can view an example of those here. https://www.credential.net/b1378d28-1db0-4fba-8174-a8827435b4b3?_ga=2.240223427.1903223037.1619739387-204885165.1618896985

### Can I use any tools I want on the exam?
Yes.  The exam is a pentest and all tools are allowed. Including Linpeas.
### How long is the exam?
The exam environment permits five full days to simulate a real pentest, though you can complete the engagement objectives ahead of time. You will have an additional two days to write a professional report and submit it to our team.

### How does the exam compare to other certifications?
In short, it really doesn’t.  The exam was designed because the industry is lacking in practical certifications.  Some certifications are multiple choice and do not test a student’s technical skills.  Other exams are hands on, but are not realistic in time allotment or attack methodology.  This exam replicates a true pentest in both attack methodology and the amount of time permitted to perform the test.

### How difficult is the exam?
Everyone is different, however, we believe that:
 - If you are a beginner, the exam will be very difficult and we strongly recommend that you purchase the associated training.
 - If you are a junior penetration tester, the exam will be difficult and may require additional training.
 - If you are a mid to senior level pentester, the exam will be of moderate difficulty.

### Is the provided training enough to pass the exam?
Yes.  It was designed for student’s to pass the exam with the training.  The training is designed for students from absolute beginner to moderate levels and will teach you the skills necessary to be successful as a penetration tester.

### Is the exam proctored?
No.  We do monitor network traffic in the exam environment and have detection mechanisms in place for cheating in the environment and the exam, but there will be no proctor or intrusive software to install on your machine.


# Training Videos:
https://academy.tcm-sec.com/

# Helpful Cheatsheets:
1. https://cheatsheet.haax.fr/
2. https://book.hacktricks.xyz/
3. https://gtfobins.github.io/
4. https://evotec.xyz/the-only-powershell-command-you-will-ever-need-to-find-out-who-did-what-in-active-directory/
5. https://github.com/S1ckB0y1337/Active-Directory-Exploitation-Cheat-Sheet#active-directory-exploitation-cheat-sheet
6. https://sqlwiki.netspi.com/
7. https://github.com/NetSPI/PowerUpSQL/wiki
8. http://pentestmonkey.net/cheat-sheet/shells/reverse-shell-cheat-sheet
9. https://sqlwiki.netspi.com/attackQueries/


## Study:
1. Buffer Overflow 
2. Linux Commands and Privilege Escalation
3. Windows Commands and Privilege Escalation
4. Metasploit Emergency Use 
5. Massive amount of current Windows Exploit that Microsoft doesn't plan to fix (because it works properly). 

## Tools I plan to use:
1. GitHub Repo (this one) — https://github.com/ciwen3/OSCP.git
2. MSFVenom Payload Creator — https://github.com/g0tmi1k/msfpc
3. Exploit-DB — https://www.exploit-db.com/
4. SearchSploit — https://www.exploit-db.com/searchsploit
```
sudo apt update && sudo apt -y install exploitdb
searchsploit -u
searchsploit -h
searchsploit afd windows local
```
   Note, SearchSploit uses an AND operator, not an OR operator. The more terms that are used, the more results will be filtered out.
   Pro Tip: Do not use abbreviations (use SQL Injection, not SQLi).
   Pro Tip: If you are not receiving the expected results, try searching more broadly by using more general terms (use Kernel 2.6 or Kernel 2.x, not Kernel 2.6.25).

5. Windows Kernel Exploits — https://github.com/SecWiki/windows-kernel-exploits
6. Linux Kernel Exploits — https://github.com/lucyoa/kernel-exploits
7. Hashcat — https://hashcat.net/hashcat/
8. John the Ripper — https://www.openwall.com/john/
9. pattern_create.rb — /usr/share/metasploit-framework/tools/exploit/pattern_create.rb
10. pattern_offset.rb — /usr/share/metasploit-framework/tools/exploit/pattern_offset.rb
11. Kali's builtin Windows Resources:
  ```
  /usr/share/windows-resources/
  /usr/share/windows-resources/binaries/
  ```

## Default Passwords for Devices
1. https://cirt.net/passwords
2. https://www.passwordsdatabase.com/
3. https://datarecovery.com/rd/default-passwords/
4. https://www.routerpasswords.com/    [So Many Adds on this Page]

## Content Discovery Tools
1. GoBuster — https://github.com/OJ/gobuster
2. Recursive GoBuster — https://github.com/epi052/recursive-gobuster
3. Nikto — https://github.com/sullo/nikto
4. dirb — https://tools.kali.org/web-applications/dirb
5. Feroxbuster — https://github.com/epi052/feroxbuster
6. Rustbuster — https://github.com/phra/rustbuster

## Scanners
1. Nmap
2. Unicornscan
3. AngryIP Scanner
4. Advanced Port Scanner

## SQL Injection Tools
1. SQLMap – Automatic SQL Injection And Database Takeover Tool - https://github.com/sqlmapproject/sqlmap
2. jSQL Injection – Java Tool For Automatic SQL Database Injection - https://github.com/ron190/jsql-injection
3. SQL – A Blind SQL-Injection Exploitation Tool - https://github.com/Neohapsis/bbqsql
4. QLMap – Automated NoSQL Database Pwnage - https://github.com/codingo/NoSQLMap
5. Whitewidow – SQL Vulnerability Scanner - https://kalilinuxtutorials.com/whitewidow/
6. DSSS – Damn Small SQLi Scanner - https://github.com/stamparm/DSSS
7. explo – Human And Machine Readable Web Vulnerability Testing Format - https://github.com/dtag-dev-sec/explo
8. Blind-Sql-Bitshifting – Blind SQL-Injection via Bitshifting - https://github.com/awnumar/blind-sql-bitshifting
9. Leviathan – Wide Range Mass Audit Toolkit - https://github.com/leviathan-framework/leviathan
10. Blisqy – Exploit Time-based blind-SQL-injection in HTTP-Headers (MySQL/MariaDB) - https://github.com/JohnTroony/Blisqy

## Note Taking:
1. CherryTree — https://www.giuspen.com/cherrytree/ (Template: https://411hall.github.io/assets/files/CTF_template.ctb)
2. KeepNote — http://keepnote.org/
3. PenTest.ws — https://pentest.ws/
4. Microsoft OneNote
5. GitHub Repo
6. Joplin with TJNull (OffSec Community Manager) template — https://github.com/tjnull/TJ-JPT
7. Obisidian Mark Down — https://obsidian.md/

## Reporting Frameworks:
1. Dradis — https://dradisframework.com/academy/industry/compliance/oscp/
2. Serpico — https://github.com/SerpicoProject/Serpico
3. Report Template
4. Created by whoisflynn — https://github.com/whosiflynn/OSCP-Exam-Report-Template
5. Created by Noraj — https://github.com/noraj/OSCP-Exam-Report-Template-Markdown

## Enumeration:
1. AutoRecon — https://github.com/Tib3rius/AutoRecon
2. nmapAutomator — https://github.com/21y4d/nmapAutomator
3. Reconbot — https://github.com/Apathly/Reconbot
4. Raccoon — https://github.com/evyatarmeged/Raccoon

## Web Enumeration:
1. Dirsearch — https://github.com/maurosoria/dirsearch
2. GoBuster — https://github.com/OJ/gobuster
3. Feroxbuster — https://github.com/epi052/feroxbuster
4. wfuzz — https://github.com/xmendez/wfuzz
5. goWAPT — https://github.com/dzonerzy/goWAPT
6. ffuf — https://github.com/ffuf/ffuf
7. Nikto — https://github.com/sullo/nikto
8. dirb — https://tools.kali.org/web-applications/dirb
9. dirbuster — https://tools.kali.org/web-applications/dirbuster

## Network Tools:
1. Impacket (SMB, psexec, etc) — https://github.com/SecureAuthCorp/impacket

## File Transfers:
1. updog — https://github.com/sc0tfree/updog

## Wordlists / Dictionaries:
1. SecLists — https://github.com/danielmiessler/SecLists
2. IIS — https://gist.github.com/nullenc0de/96fb9e934fc16415fbda2f83f08b28e7

## Payload Generators:
1. Reverse Shell Generator — https://github.com/cwinfosec/revshellgen
2. Windows Reverse Shell Generator — https://github.com/thosearetheguise/rev
3. MSFVenom Payload Creator — https://github.com/g0tmi1k/msfpc

## PHP Reverse Shells:
1. Windows PHP Reverse Shell — https://github.com/Dhayalanb/windows-php-reverse-shell
2. PenTestMonkey Unix PHP Reverse Shell — http://pentestmonkey.net/tools/web-shells/php-reverse-shell

## Terminal Related:
1. tmux — https://tmuxcheatsheet.com/ (cheat sheet)
2. tmux-logging — https://github.com/tmux-plugins/tmux-logging
3. Oh My Tmux — https://github.com/devzspy/.tmux
4. screen — https://gist.github.com/jctosta/af918e1618682638aa82 (cheat sheet)
5. Terminator — http://www.linuxandubuntu.com/home/terminator-a-linux-terminal-emulator-with-multiple-terminals-in-one-window
6. vim-windir — https://github.com/jtpereyda/vim-windir

## Exploits:
1. Exploit-DB — https://www.exploit-db.com/
2. AutoNSE — https://github.com/m4ll0k/AutoNSE

## Windows Exploits:
1. Windows Kernel Exploits — https://github.com/SecWiki/windows-kernel-exploits
2. LOLBins - https://lolbas-project.github.io/#
3. Windows Takeover completely from Linux — https://www.sprocketsecurity.com/blog/the-ultimate-tag-team-petitpotam-and-adcs-pwnage-from-linux
4. Windows Credentials — https://www.alteredsecurity.com/post/fantastic-windows-logon-types-and-where-to-find-credentials-in-them
5. Everything Below — https://github.com/cfalta/MicrosoftWontFixList/blob/main/README.md
6. https://github.com/GossiTheDog/HiveNightmare
7. https://github.com/GossiTheDog/SystemNightmare
8. https://github.com/leechristensen/SpoolSample
9. https://github.com/topotam/PetitPotam
10. https://github.com/antonioCoco/RemotePotato0
11. https://github.com/S3cur3Th1sSh1t/SharpNamedPipePTH
12. https://github.com/cube0x0/CVE-2021-1675

## Linux Exploits: 
1. Linux Kernel Exploits — https://github.com/lucyoa/kernel-exploits
2. GTFOBins (Bypass local restrictions) — https://gtfobins.github.io/

## Password Brute Forcers:
1. BruteX — https://github.com/1N3/BruteX
2. Hashcat — https://hashcat.net/hashcat/
3. John the Ripper — https://www.openwall.com/john/
4. Post-Exploitation / Privilege Escalation
5. LinEnum — https://github.com/rebootuser/LinEnum
6. linprivchecker —https://www.securitysift.com/download/linuxprivchecker.py
7. Powerless — https://github.com/M4ximuss/Powerless
8. PowerUp — https://github.com/HarmJ0y/PowerUp
9. Linux Exploit Suggester — https://github.com/mzet-/linux-exploit-suggester
10. Windows Exploit Suggester — https://github.com/bitsadmin/wesng
11. Windows Privilege Escalation Awesome Scripts (WinPEAS) — https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS
12. Linux Privilege Escalation Awesome Script (LinPEAS) — https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS
13. GTFOBins (Bypass local restrictions) — https://gtfobins.github.io/
14. Get GTFOBins — https://github.com/CristinaSolana/ggtfobins
15. sudo_killer — https://github.com/TH3xACE/SUDO_KILLER

## Privilege Escalation Practice:
1. Local Privilege Escalation Workshop — https://github.com/sagishahar/lpeworkshop
2. Linux Privilege Escalation — https://www.udemy.com/course/linux-privilege-escalation/
3. Windows Privilege Escalation — https://www.udemy.com/course/windows-privilege-escalation/

## Extra Practice:
1. HTB/Vulnhub like OSCP machines (Curated by OffSec Community Manager TJNull)— https://docs.google.com/spreadsheets/d/1dwSMIAPIam0PuRBkCiDI88pU3yzrqqHkDtBngUHNCw8/edit#gid=1839402159
2. Virtual Hacking Labs — https://www.virtualhackinglabs.com/
3. HackTheBox (Requires VIP for Retired machines) — https://www.hackthebox.eu/
4. Vulnhub — https://www.vulnhub.com/
5. Root-Me — https://www.root-me.org/
6. Try Hack Me — https://tryhackme.com
7. OverTheWire — https://overthewire.org (Linux basics)

### All of my Public projects, opinions and advice are offered “as-is”, without warranty, and disclaiming liability for damages resulting from using any of my software or taking any of my advice.
