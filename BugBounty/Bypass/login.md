# Testing password fields:
1. Forced Browsing
2. Parameter Modification
3. Session Identifier Prediction
4. SQL Injection within Login Forms
5. Stealing cookie
6. Trying default / easy to guess usernames and passwords
7. Phishing

https://twitter.com/secalert/status/1353303406044184577?s=21
```
%01%E2%80%AEalert%0D%0A
%01%E2%80%AEal%efert%0D%0A
%01%E2%80%AEal%bbert%0D%0A
%01%E2%80%AEal%bfert%0D%0A
```

Let's break it down:
1. %01 is SOH ("start of heading" or "U+0001")
2. %e2%80%ae is RTLO ("right-to-left-override" or "U+202E")
3. %0d%0a is CRLF

Test cases on login:
1. can I log in only using %01?
2. without the CRLF in it?
3. is trela accepted instead of alert? (due to RTLO)


FEFF itself is for UTF-16 — in UTF-8 it is more commonly known as 0xEF,0xBB, or 0xBF








## so you have a Login page with username and password and a login button.
- Try to enumerate the usernames by monitoring the errors. Like username already exist (then it will be a problem.).
- Is the login page is in the HTTPS? 
- Is the credentials sent over HTTPS?
- default username password
- SQL injection.
- When you log in to your account sees the parameters carefully, is there any parameter like User-id. And if there is any then try to IDOR.
- View the source code for information that may allow you to breach the login page. Developer comments, variables used for authentication
- View the page to see if its using a known framework with security issues. Find the version number and look up related CVEs
- Proxy the request with burp suite or owasp zap and view the content. Tamper with information being passed across to see if it allows access
- View the content of cookies if there are any to see if that data allows access (seriously I've come across access=true in the past)
- Try going around the login page if you can guess some urls, they may have poor access controls on the page you are trying to get to
- View the site itself for information. Use something like dirbuster to see if there are any directories open to you that relate to the login page. Maybe a user list of plain text password file
- See what the login page is being hosted on. Maybe there is an exploit on the host platform you can use to gain access or get around the page
- Use a list of user / passwords from previous breaches to try brute force access




# Find Hidden Files
- sub.target.com/web/admin/ => 302 redirect to main domain
- http://sub.target.com/web/aDmiN/ =>200 ok admin login page
- http://sub.target.com/web/aDmiN/FUZZ =>$Critical sensitive files$ 


# Authentication Bypass:
- Try changing Cookie values --> admin
- Try registering as Admin, admiN, admin<space>, etc
- Check for Info Leaks in 302 Redirects 
- Check for Basic SQLi on Login


# 2FA Bypass:
- Site is using Google Authenticator for 2FA.
- There is an endpoint which will give you the QR Code / auth code to add into your Google Authenticator app.
- Once the setup is done user can perform 2FA with Google app and login frok the next time.


# Sustained Credentials
- Login with same creds in two diff browsers (eg A,B)
- Change passwd in A 
- B is not affected


# Bypass Login for Endpoint Applications
- Sign-in to site and collect endpoints. 
- Try accessing endpoints directly that require users to sign in, without signing in. 
- Some applications might not redirect you to the login page.
- Read the JS files

# Account takeover / security question bypass:
https://twitter.com/ShawarkOFFICIAL/status/1362251957088509953
- Request user password reset
- Enter any invalid security question answer
- Invalid answer => statusCode:2011
- Change response code to statusCode:2010
- Password change page appears and any account can be taken over






# OTP
https://www.exploit-db.com/google-hacking-database
search: otp

1. Try all zeros: 0000 or 000000
2. Try by passing the rate limit to brute force https://github.com/ciwen3/BugBounty/blob/main/Bypass-Rate-Limit.md
3. Input negative number?
4. If the client side browser is used to secure the website: https://amitp200.medium.com/how-i-bypass-otp-verification-in-account-registration-process-ce698654a7af
5. https://twitter.com/krizzsk/status/1248261472838279169
- Find registered endpoint via JS file "/register"
- Go to that endpoint and use a registered and active username with the wrong password
- Capture the logon request in Burp
- Modify the request by changing:
```
login_method:"Normal"
```
to 
```
login_method:"Anything"
```
- Success message may appear without logging in
- Reload the same success page and capture the request to see if it has a valid session cookie
- Copy and Paste the session cookie for every API call made (ie. Change Password, Email, Etc)
- Hopefully you now have access to the victim account



# Git
## Fuzzing
```
/.git/FUZZ 
```
(use custom .git wordlist)

## 403 Bypass
```
/.git => 403
/.git/config/ => 200
/.git/config/* => 200
```

# 403 Bypass
https://github.com/KathanP19/HowToHunt/blob/master/Status_Code_Bypass/403Bypass.md

https://en.wikipedia.org/wiki/Fully_qualified_domain_name
## Directory Based
If you see directory with no slash at end then do these acts there
```
site.com/secret => 403
site.com./secret => 200
site.com/secret/* => 200
site.com/secret/./ => 200
```
## File Base
If you see file without any slash at end then do these acts there
```
site.com/secret.txt => 403
site.com./secret.txt => 200
site.com/secret.txt/ => 200
site.com/%2f/secret.txt/ => 200
```
## Protocol Base
Well, sound wired but check out the example for better understanding
```
https://site.com/secret => 403
http://site.com/secret => 200
```

## Payloads
```
/
/*
/%2f/
/./
./.
/*/
```
## Header
https://observationsinsecurity.com/2020/08/09/bypassing-403-to-get-access-to-an-admin-console-endpoints/
```
X-Forwarded-For: 127.0.0.1
```
## Tools
Here is a Tool I found on twitter.

https://github.com/yunemse48/403bypasser



curl -s -I https://[host]/global-protect/portal/css/login.css | grep Last-Modified
