# this is a work in progress and is here for unsorted things. 
```
https://twitter.com/Bugcrowd/status/1358483170371522561

Go to project's github issue
And sort by,
label:"security" 
label:"vulnerability"
label:"bug"
label:"serious" 
label:"wontfix"
label:"error"
label:"cannot-reproduce"

====================================================

Have an api endpoint but just displays "403 forbidden" try to do this:

1. api/v1/users   -> 403
2. api/v1/../users  -> 200
or
3. api/v1/profile  -> 200   but api/v1/users ->403
then
api/v1/profile/../users   -> 200

====================================================

If you're testing .NET application try to brute force directories to find trace.axd file this file logs every request like GET and POST to the application if you found one accessible publicly then congrats it a P1. 

====================================================

Okay, so this is super simple, yet effective:
Each time you test an app, scroll over the HTTP history in burp, make a note of:
A) the technology mostly used in it
B) any/all interesting paths/endpoints
Through that all in a sublime file and go on to make a fresh wordlist on it!
This would help in:
A) CMS/Technology specific approach
B) A general know-how of how developers look to name their paths.
C) Brand new custom wordlist!

====================================================

collect every js file .using 1 burp suite 2 waybackurl 3 crawling . find sensetive keys,credentials,new endpoint.

====================================================

signup victim email
set username %0dusername
if %0d srtiped in mail victim not signup with this email

====================================================

Dont be lazy to test for default credentials. It could be a surprise for you !

====================================================

Always check for Js contain sensitive files like hardcoded credentials

====================================================

look for Github dorks with the associated company Name it might leak DB passwords / auth keys /employee details
easy to find and get you direct P1 /P2

====================================================

Use burp match and replace to get hidden features also privilege types of bugs.

====================================================

when testing agaisnt aliyun WAF use console.log(1) instead of alert(1) to see if ur payload is working well

====================================================

Try changing request methods and content types to bypass 403

Fuzz everything, change request method and accept header, post JSON data as XML and so on

Always try to manipulate the response

====================================================

Always check for URL injection attack

====================================================
Burp extensions:
https://github.com/PortSwigger/turbo-intruder
https://github.com/bytebutcher/burp-send-to
https://github.com/bytebutcher

====================================================

https://github.com/harsh-bothra/learn365

====================================================

https://canarytokens.org/generate

====================================================

https://gowsundar.gitbook.io/book-of-bugbounty-tips/
https://github.com/KathanP19/HowToHunt/blob/master/Status_Code_Bypass/403Bypass.md
https://github.com/KathanP19/HowToHunt




```
