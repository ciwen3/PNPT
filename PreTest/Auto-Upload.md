# Automatically upload notes and screenshots

## create OSCP-git.sh
```
nano OSCP-git.sh
```
Copy and paste the text below into nano
```
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
```
Make script executable
```
chmod +x OSCP-git.sh
```

## create OSCP-expect.sh
```
nano OSCP-expect.sh
```
Copy and paste the text below into nano, change the username and password to the appropriate values.

**For security reasons this should not be kept in a public Github repo.**
```
#!/usr/bin/expect -f

set timeout -1
spawn ./OSCP-git.sh

# Interact with the login using expect
expect "Username for 'https://github.com':"
send -- "<username>\n"
expect "Password for 'https://<username>@github.com':"
send -- "<password>\n"
expect eof
```
Make script executable
```
chmod +x OSCP-expect.sh
```

## from terminal run 
```
for i in {1..1000}; do ./OSCP-expect.sh; done
```
