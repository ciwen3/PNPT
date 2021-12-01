# Setup Kali

### 1. Install Kali Linux https://www.kali.org/downloads/

### 2. Update Kali: 
```
wget -q https://www.virtualbox.org/download/oracle_vbox_2016.asc -O- | sudo apt-key add -
wget -q https://www.virtualbox.org/download/oracle_vbox.asc -O- | sudo apt-key add -
sudo apt update && sudo apt upgrade -y && sudo apt install -y curl wget ssh openvpn git flameshot expect python3 python3-pip asciinema cherrytree virtualbox feroxbuster sublist3r 
```

### 3. Install pip for Python2: 
```
curl https://bootstrap.pypa.io/pip/2.7/get-pip.py -o get-pip.py
python get-pip.py
```

### 4. Install Impacket
```
pip3 install impacket
git clone https://github.com/SecureAuthCorp/impacket.git
cd impacket/
pip3 install .
```

### 5. Install Feroxbuster https://github.com/epi052/feroxbuster

### 6. Autosave all commands to History forever with a timestamp
taken from: http://jesrui.sdf-eu.org/remember-all-your-bash-history-forever.html
```
# Append the following lines to /etc/bash.bashrc:

HISTTIMEFORMAT='%F %T '
HISTFILESIZE=-1
HISTSIZE=-1
HISTCONTROL=ignoredups
HISTIGNORE=?:??

# append to history, don't overwrite it
shopt -s histappend                 
# attempt to save all lines of a multiple-line command in the same history entry
shopt -s cmdhist
# save multi-line commands to the history with embedded newlines
shopt -s lithist
```

### 7. Timestamp in Terminal (for screenshots)
taken from: https://www.contextis.com/en/blog/logging-like-a-lumberjack
```
cp ~/.bashrc ~/.bashrc.back
nano ~/.bashrc
# find the line(s) with PS1= and 
# add the following inside the ' '
[`date +"%d-%b-%Y %T"`] > 
# [21-Feb-2020 10:57:20] > 
```

### 8. clone this repo 
```
git clone https://github.com/ciwen3/OSCP.git
```

### 9. Flameshot Configuration: 
right click on the flameshot icon > Configuration > General > uncheck "Show Desktop Notifications"

to automatically take screenshots (every 60 seconds) run this in terminal. 
```
while true; do flameshot full -p ~/Pictures/ ; sleep 60 ; done
```

### 10. CherryTree 
Configuration: Edit > Preferences > Miscellaneous > Auto Save Every __ Minutes

### 11. Record Terminal output
install asciinema 
```
sudo apt install asciinema -y && mkdir ~/asciinema
```
add the following to the bottom of ~/.bashrc and ~/.zshrc
```
asciinema rec ~/asciinema/OSCP-$(date +"%d-%b-%Y-%T").cast
```

### 12. Setup and test MSFConsole (just in case)
https://github.com/ciwen3/OSCP/blob/master/Metasploit/MSFconole.md

### 13. Foxy Proxy & Burp Suite
https://addons.mozilla.org/en-US/firefox/addon/foxyproxy-standard/
- create new
- name: burp
- IP: 127.0.0.1
- Port: 8080
browse to: http://burpsuite to install the certificate



# Setup Windows 10 VM
## Settings:
1. Antivirus turned off
2. firewall turned off

## Software:
1. Immunity Debugger - https://www.immunityinc.com/products/debugger/index.html
2. moana.py - https://github.com/corelan/mona
3. GitBash - https://gitforwindows.org/
4. Firefox - https://www.mozilla.org/en-US/firefox/new/
5. Foxy Proxy - https://addons.mozilla.org/en-US/firefox/addon/foxyproxy-standard/
6. Burp Community edition - https://portswigger.net/burp/communitydownload
7. Java - https://www.java.com/en/download/manual.jsp
8. OWASP ZAP - https://www.zaproxy.org/

## Attack Checklist:
1. https://book.hacktricks.xyz/windows/checklist-windows-privilege-escalation

# OSCP Start Checklist:
1. start Automatic Screenshots (saving to github folder)
	- [ ] Host: WinKey + G, snipping tool
	- [ ] VirtualBox: VM settings > Display > Recording > Enable Recording, Frame Size: 1024x768 (4:3), Frame Rate: 1 fps, Video Quality: high
	- [ ] Windows VM: snipping tool
	- [ ] Kali VM: Flameshot - ```while true; do flameshot full -p ~/Pictures/ ; sleep 60 ;  done``` 
	
	```
	PrtSc – Save a screenshot of the entire screen to the “Pictures” directory.
	Shift + PrtSc – Save a screenshot of a specific region to Pictures.
	Alt + PrtSc  – Save a screenshot of the current window to Pictures.
	Ctrl + PrtSc – Copy the screenshot of the entire screen to the clipboard.
	Shift + Ctrl + PrtSc – Copy the screenshot of a specific region to the clipboard.
	Ctrl + Alt + PrtSc – Copy the screenshot of the current window to the clipboard.
	```
2. start script to auto upload my notes and screenshoots to private github account
	https://github.com/ciwen3/OSCP/blob/master/PreTest/Auto-Upload.md
	
3. connect OSCP VPN
4. Login to OSCP website

# TODO:
1. Script to automatically do all the things on this list. 

## Not sure about:
### 1. Install OBS studio?? gnome-screenshot?? imagemagick??
### 2. 
