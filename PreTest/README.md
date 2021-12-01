# Update Kali
```
sudo apt update 
sudo apt full-upgrade -y 
sudo apt install -y asciinema bloodhound bzip2 cherrytree curl dirsearch docker expect exploitdb flameshot ffuf gcc gifsicle git gobuster golang gzip imagemagick inkscape libsqlite3-dev libxslt-dev libxml2-dev nikto nishang openvpn p7zip-full perl python3 python3-pip realtek-rtl88xxau-dkms ssh unzip veil virtualbox wget zip zlib1g-dev
sudo apt autoremove
```
# Update Nmap Scripts
```
sudo nmap --script-updatedb
```
# Install pip packages
```
pip3 install updog
pip3 install wfuzz
pip3 install ldap3 dnspython
pip3 install ldapdomaindump
```
# install Veil 3  https://github.com/Veil-Framework/Veil
```
/usr/share/veil/config/setup.sh --force --silent
```
# change file/folder permissions
```
sudo chmod -R 777 /usr/share/wordlists
sudo chmod -R 777 /opt
```
# Update $PATH
```
export PATH=$PATH:~/.local/lib
export PATH=$PATH:/opt
```
# feroxbuster
```
wget https://github.com/epi052/feroxbuster/releases/latest/download/feroxbuster_amd64.deb.zip
unzip feroxbuster_amd64.deb.zip
sudo apt install ./feroxbuster_*_amd64.deb
rm ./feroxbuster_*_amd64.deb
rm ./feroxbuster_amd64.deb.zip
```
# Install pip for Python2:
```
curl https://bootstrap.pypa.io/get-pip.py -o get-pip.py
python get-pip.py
```
# install impacket
```
sudo docker build -t "impacket:latest" .
```

# install wpscan docker image
```
sudo docker pull wpscanteam/wpscan
sudo docker run -it --rm wpscanteam/wpscan --update
```

# exploits:
```
cd /opt
wget https://www.securitysift.com/download/linuxprivchecker.py
git clone https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite.git
git clone https://github.com/PowerShellMafia/PowerSploit.git
git clone https://github.com/SecWiki/windows-kernel-exploits.git
git clone https://github.com/SecWiki/linux-kernel-exploits.git
git clone https://github.com/tennc/webshell.git
git clone https://github.com/swisskyrepo/PayloadsAllTheThings.git
git clone https://github.com/rsmudge/ZeroLogon-BOF.git
git clone https://github.com/carlospolop/PEASS-ng.git
git clone https://github.com/PowerShellMafia/PowerSCCM.git
git clone https://github.com/411Hall/JAWS.git
git clone https://github.com/frizb/Windows-Privilege-Escalation.git
git clone https://github.com/itm4n/PrivescCheck.git
git clone https://github.com/johnchakauya/wesng.git
git clone https://github.com/leechristensen/SpoolSample.git
git clone https://github.com/topotam/PetitPotam.git
git clone https://github.com/antonioCoco/RemotePotato0.git
git clone https://github.com/S3cur3Th1sSh1t/SharpNamedPipePTH.git
git clone https://github.com/cube0x0/CVE-2021-1675.git
git clone https://github.com/GossiTheDog/HiveNightmare.git
git clone https://github.com/GossiTheDog/SystemNightmare.git
git clone https://github.com/LOLBAS-Project/LOLBAS.git
# my repo
git clone https://github.com/ciwen3/OSCP.git
# other
git clone https://github.com/LOLBAS-Project/LOLBAS.git
git clone https://github.com/mishmashclone/OlivierLaflamme-Cheatsheet-God.git
git clone https://github.com/vjeantet/hugo-theme-docdock.git
git clone https://github.com/NetSPI/PowerUpSQL.git
# tools
git clone https://github.com/sullo/nikto.git
git clone https://github.com/phra/rustbuster.git
git clone https://github.com/Tib3rius/AutoRecon.git
git clone https://github.com/21y4d/nmapAutomator.git
git clone https://github.com/ffuf/ffuf.git
git clone https://github.com/sullo/nikto.git
git clone https://github.com/cwinfosec/revshellgen.git
git clone https://github.com/thosearetheguise/rev.git
git clone https://github.com/mzet-/linux-exploit-suggester.git
git clone https://github.com/HarmJ0y/PowerUp.git
git clone https://github.com/BloodHoundAD/BloodHound
git clone https://github.com/byt3bl33d3r/CrackMapExec.git
git clone https://github.com/jonaslejon/malicious-pdf.git
git clone https://github.com/tennc/webshell.git

git clone https://github.com/dzonerzy/goWAPT.git
cd goWAPT
make 
sudo make install

cd /opt
git clone https://github.com/fox-it/mitm6.git
cd mitm6/
pip3 install .
sudo python3 ./setup.py install
```
# Wordlists
```
cd /usr/share/wordlists
wget https://gist.githubusercontent.com/nullenc0de/96fb9e934fc16415fbda2f83f08b28e7/raw/146f367110973250785ced348455dc5173842ee4/content_discovery_nullenc0de.txt
wget https://gist.githubusercontent.com/gladiatx0r/1ffe59031d42c08603a3bde0ff678feb/raw/a1db6730886a423c7639bb226beb331891bbb2a1/Workstation-Takeover.md
wget https://crackstation.net/files/crackstation.txt.gz
wget https://crackstation.net/files/crackstation-human-only.txt.gz
wget http://downloads.skullsecurity.org/passwords/john.txt.bz2
wget http://downloads.skullsecurity.org/passwords/facebook-phished.txt.bz2
wget http://downloads.skullsecurity.org/passwords/porn-unknown.txt.bz2
wget http://downloads.skullsecurity.org/passwords/facebook-pastebay.txt.bz2
wget http://downloads.skullsecurity.org/passwords/elitehacker.txt.bz2
wget http://downloads.skullsecurity.org/passwords/hak5.txt.bz2
wget http://downloads.skullsecurity.org/passwords/hotmail.txt.bz2
wget http://downloads.skullsecurity.org/passwords/myspace.txt.bz2
wget http://downloads.skullsecurity.org/passwords/phpbb.txt.bz2
wget https://downloads.pwnedpasswords.com/passwords/pwned-passwords-sha1-ordered-by-count-v7.7z
wget https://downloads.pwnedpasswords.com/passwords/pwned-passwords-ntlm-ordered-by-count-v7.7z
wget http://www.petefinnigan.com/default/oracle_default_passwords.csv
wget https://raw.githubusercontent.com/danielmiessler/SecLists/master/Passwords/Default-Credentials/default-passwords.csv
wget https://raw.githubusercontent.com/drtychai/wordlists/master/fasttrack.txt
wget https://raw.githubusercontent.com/trustedsec/social-engineer-toolkit/master/src/fasttrack/wordlist.txt

gunzip ./*.gz
bunzip2 ./*.bz2
7z x ./*.7z

git clone https://github.com/danielmiessler/SecLists.git
git clone https://github.com/drtychai/wordlists.git
```
# Create Asscinema
```
cd
mkdir ~/asciinema
```
# Update zshrc and bashrc
```
sudo cat <<EOF >> /etc/zsh/zshrc
HISTTIMEFORMAT='%F %T '
HISTFILESIZE=-1
HISTSIZE=-1
HISTCONTROL=ignoredups
HISTIGNORE=?:??
EOF
```
```
sudo cat <<EOF >> /etc/bash.bashrc
HISTTIMEFORMAT='%F %T '
HISTFILESIZE=-1
HISTSIZE=-1
HISTCONTROL=ignoredups
HISTIGNORE=?:??
EOF
```

# Ceate Sripts for Rtaining Data
```
cat <<EOF > ~/flameshot.sh
#!/bin/bash
while true; do flameshot full -p ~/Pictures/ ; sleep 60 ; done
EOF
chmod +x ~/flameshot.sh
```
```
cat <<EOF > ~/OSCP-git.sh
#!/bin/bash
# upload all notes and screen shots to github every 5 min
sleep 300
# Test file creation
# touch 'new-'$(date +"%H:%M-%d-%b-%Y")'.txt'
# Add, Commit and Upload files to Github
git add -A
git commit -m update
git push origin main
# for older Github accounts use below:
# git push origin master 
EOF
chmod +x ~/OSCP-git.sh
```
```
cat <<EOF > ~/OSCP-expect.sh
#!/usr/bin/expect -f
set timeout -1
spawn ./OSCP-git.sh
# Interact with the login using expect
expect "Username for 'https://github.com':"
send -- "<username>\n"
expect "Password for 'https://<username>@github.com':"
send -- "<password>\n"
expect eof
EOF
chmod +x ~/OSCP-expect.sh
```

```
sudo cat <<EOF >> ~/.zshrc
echo ""
echo "Checklist:"
echo "=========="
echo 'asciinema rec ~/asciinema/OSCP-\$(date +"%d-%b-%Y-%T").cast'
echo ""
echo "Auto upload github repo:"
echo "while true; do ~/OSCP-expect.sh; done &"
echo ""
echo "Start screebshots:"
echo "~/flameshot.sh &"
echo ""
echo "To Use Impacket Docker File Run:"
echo 'sudo docker run -it --rm "impacket:latest"'
echo ""
echo "sudo docker run -it --rm wpscanteam/wpscan --url https://example.com/ --enumerate u"
echo ""
echo "to leave docker run exit"
EOF
```
```
sudo cat <<EOF >> ~/.bashrc
echo ""
echo "Checklist:"
echo "=========="
echo 'asciinema rec ~/asciinema/OSCP-\$(date +"%d-%b-%Y-%T").cast'
echo ""
echo "Auto upload github repo:"
echo "while true; do ~/OSCP-expect.sh; done &"
echo ""
echo "Start screebshots:"
echo "~/flameshot.sh &"
echo ""
echo "To Use Impacket Docker File Run:"
echo 'sudo docker run -it --rm "impacket:latest"'
echo ""
echo "sudo docker run -it --rm wpscanteam/wpscan --url https://example.com/ --enumerate u"
echo ""
echo "to leave docker run exit"
EOF
```
# MSFconsole setup
```
service postgresql start
sudo msfdb init
sudo chmod 777 /usr/share/metasploit-framework/.bundle/config
```
# Print Check List of things that need to be done manually
```
cat <<EOF 
Checklist:
==========
CherryTree:
Configuration: Edit > Preferences > Miscellaneous > Auto Save Every __ Minutes

MSF setup:
msfconsole
db_status
bundle install

EOF
```
