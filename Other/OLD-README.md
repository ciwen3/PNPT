# OSCP Prep Notes

This is where I will be keeping all my references, notes, and code that I plan to use for the OSCP. I am making them public so that I can share this with the monitors, once I take the OSCP. 

## Study:
1. Buffer Overflow 
2. Linux Commands and Privilege Escalation
3. Windows Commands and Privilege Escalation
4. Metasploit Emergency Use (in case I am running out of time and need some more points)
5. ZeroLogon Exploit (just in case)

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

## Content Discovery Tools
1. GoBuster — https://github.com/OJ/gobuster
2. Recursive GoBuster — https://github.com/epi052/recursive-gobuster
3. Nikto — https://github.com/sullo/nikto
4. dirb — https://tools.kali.org/web-applications/dirb
5. Feroxbuster — https://github.com/epi052/feroxbuster
6. Rustbuster — https://github.com/phra/rustbuster

# Exam Guide:
https://help.offensive-security.com/hc/en-us/articles/360040165632-OSCP-Exam-Guide

## Exam Proof Filenames
1. proof.txt - This file is only accessible to the root or Administrator user and can be found under the /root/ directory or the Administrator Desktop. This file is available on every target machine.
2. local.txt - This file is accessible to an un-privileged user account and can only be found on certain machines. The targets containing these files are detailed in your control panel.

## Point Allocation
1. The order in which the exam machines are documented inside your exam report is the same order in which the exam machines will be graded and valued
2. Points will be awarded for partial and complete administrative control of each target machine
3. Each machine has a specific set of objectives that must be met in order to receive full points
4. You must achieve a minimum score of 70 points to pass the exam
5. It is possible to achieve a maximum of 100 points on the exam
6. Specific objectives and point values for each machine are located in your exam control panel

## Point Disqualification
You will receive no points for a specific target for the following:
1. Using a restricted tool
2. Using Metasploit Auxiliary, Exploit, or Post modules on multiple machines
3. Using the Meterpreter payload on multiple machines
4. Using LinPeas ( https://twitter.com/_superhero1/status/1385206684109447168 & https://www.reddit.com/r/oscp/comments/mw4idk/heads_up_dont_use_linpeas_on_the_exam/ UPDATE: https://www.offensive-security.com/offsec/understanding-pentest-tools-scripts/ )
5. Failure to provide the local.txt and proof.txt file contents in both the control panel and in a screenshot

Exam Restrictions from https://help.offensive-security.com/hc/en-us/articles/360040165632-OSCP-Exam-Guide
You cannot use any of the following on the exam:

- Spoofing (IP, ARP, DNS, NBNS, etc)
- Commercial tools or services (Metasploit Pro, Burp Pro, etc.)
- Automatic exploitation tools (e.g. db_autopwn, browser_autopwn, SQLmap, SQLninja etc.)
- Mass vulnerability scanners (e.g. Nessus, NeXpose, OpenVAS, Canvas, Core Impact, SAINT, etc.)
- Features in other tools that utilize either forbidden or restricted exam limitations

Any tools that perform similar functions as those above are also prohibited. You are ultimately responsible for knowing what features or external utilities any chosen tool is using. The primary objective of the OSCP exam is to evaluate your skills in identifying and exploiting vulnerabilities, not in automating the process.

You may however, use tools such as Nmap (and its scripting engine), Nikto, Burp Free, DirBuster etc. against any of your target systems.

## Metasploit Restrictions
The usage of Metasploit and the Meterpreter payload are restricted during the exam. You may only use Metasploit modules ( Auxiliary, Exploit, and Post ) or the Meterpreter payload against one single target machine of your choice. Once you have selected your one target machine, you cannot use Metasploit modules ( Auxiliary, Exploit, or Post ) or the Meterpreter payload against any other machines.

Metasploit/Meterpreter should not be used to test vulnerabilities on multiple machines before selecting your one target machine ( this includes the use of check ) . You may use Metasploit/Meterpreter as many times as you would like against your one target machine.

If you decide to use Metasploit or Meterpreter on a specific target and the attack fails, then you may not attempt to use it on a second target. In other words, the use of Metasploit and Meterpreter becomes locked in as soon as you decide to use either one of them.

```
You may use the following against all of the target machines:
1. multi handler (aka exploit/multi/handler)
2. msfvenom
3. pattern_create.rb
4. pattern_offset.rb
```

# Unofficial OSCP Approved Tools:
info taken from: https://medium.com/@falconspy/unofficial-oscp-approved-tools-b2b4e889e707

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
5. Web Related
6. Dirsearch — https://github.com/maurosoria/dirsearch
7. GoBuster — https://github.com/OJ/gobuster
8. Feroxbuster — https://github.com/epi052/feroxbuster
9. wfuzz — https://github.com/xmendez/wfuzz
10. goWAPT — https://github.com/dzonerzy/goWAPT
11. ffuf — https://github.com/ffuf/ffuf
12. Nikto — https://github.com/sullo/nikto
13. dirb — https://tools.kali.org/web-applications/dirb
14. dirbuster — https://tools.kali.org/web-applications/dirbuster
15. GTFOBins (Bypass local restrictions) — https://gtfobins.github.io/

## Network Tools:
1. Impacket (SMB, psexec, etc) — https://github.com/SecureAuthCorp/impacket

## File Transfers:
1. updog — https://github.com/sc0tfree/updog

## Wordlists / Dictionaries:
1. SecLists — https://github.com/danielmiessler/SecLists

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
2. Windows Kernel Exploits — https://github.com/SecWiki/windows-kernel-exploits
3. AutoNSE — https://github.com/m4ll0k/AutoNSE
4. Linux Kernel Exploits — https://github.com/lucyoa/kernel-exploits

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
