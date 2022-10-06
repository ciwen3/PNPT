# Command History
1. add a space at the front of the command you want to run ```" ls" instead of "ls"```
2. to disable history ```export HISTFILE=/dev/null```
3. to disable history ```unset HISTFILE```
4. 3. to disable history ```export HISTSIZE=0```
5. hide command by masking it as syslogd  ```exec -a syslogd nmap -TO 10.0.0.1/24```
6. start a background hidden process as syslogd ```exec -a syslogd nmap -TO 10.0.0.1/24 &>nmap.log &```
7. start a background hidden process as syslogd ```exec -a syslogd nmap -TO 10.0.0.1/24 &>nmap.log & kill -9 $$```




# Password Dumping/Cracking
1. add a coma in the password so a csv file will split it into 2 fields
2. EICAR as a password to quarantine the password list apon cracking the password ```X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*``` https://secure.eicar.org/eicar.com.txt
3. 
4. 
