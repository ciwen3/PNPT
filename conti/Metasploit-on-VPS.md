# Installing metasploit on VPS
```
apt-get update
apt-get install curl
apt-get install tmux
apt-get install default-jdk
apt-get install postgresql
apt-get install nano
apt-get install gpg
curl https://raw.githubusercontent.com/rapid7/metasploit-omnibus/master/config/templates/metasploit-framework-wrappers/msfupdate.erb > msfinstall

chmod +x msfinstall
./msfinstall
```
then open
```
nano /opt/metasploit-framework/bin/msfdb
```
we find and comment on these lines
```
# if grep -q kali /etc/os-release; then
# echo "Metasploit running on Kali Linux as root, using system database
```
keep CTRL+O
```
msfdb init
```
