# IMAP Tests
https://easyengine.io/tutorials/mail/server/testing/imap/
## Connect to server
```
telnet example.com 143
openssl s_client -crlf -connect example.com:993
```
## IMAP Test Commands
```
01 LOGIN admin@example.com password
02 LIST "" *
03 SELECT INBOX
04 STATUS INBOX (MESSAGES)
05 FETCH 1 ALL
06 LOGOUT
```
