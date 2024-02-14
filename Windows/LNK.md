




# LNK + HTA Polyglot:
1. create the LNK in windows (right click on file and select create shortcut)
2. open the LNK
   - right click the newly created shorcut
   - selct properties
   - change information in "Target:" to the command you want it to run
     - could run any command from download next stage or create new user or call this file to execute polyglot
4. create HTA file
    - this can include raw code. 
5. combine the two files on the command line
    - assuming the LNK file is named shell.lnk and the HTA file is named code.hta and create a filename shellcode.lnk
```cmd
C:\> copy /b shell.lnk+code.hta shellcode.lnk
```
   - NOTE: you can use a double extension to hide the LNK extension.
   - assuming the LNK file is named shell.jpg.lnk and the HTA file is named code.hta and create a filename shellcode.jpg.lnk
```cmd
C:\> copy /b shell.jpg.lnk+code.hta shellcode.jpg.lnk
```
   - this will make the file appear as shellcode.jpg in file explorer do to the way windows wants to hide certain extensions. 



### References: 
1. https://badoption.eu/blog/2023/09/28/ZipLink.html
2. https://599cd.com/tips/hta/beginner/B1/
3. https://learn.microsoft.com/en-us/previous-versions/ms536495(v=vs.85)
