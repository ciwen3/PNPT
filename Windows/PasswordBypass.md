# Windows 7 - Windows 11
## Circumvent the Password:
This might work on other versions as well.

1. Boot from a Linux USB
2. Mount the computers hard drive
3. go to the windows\system32 folder
4. rename sethc.exe as sethc3.exe
5. make a copy of cmd.exe (in the same folder)
6. rename copy of cmd as sethc.exe
7. reboot computer into Windows 7
8. at login screen hit SHIFT key 5 times
9. this will bring up cmd
  - enter the following command to list all users on the system
```
> net user 
> net user "username" *
```
replace "username" with the users actual name.

enter the new password or leave blank for no password (press Enter)

reboot and login


# From within windows:

1. cause a system issue by holding the power button while the Windows is loading (before the login screen)
2. reboot and select REPAIR
3. if it askes to restore the system, cancel that
4. let it scan the system for issues until you get a message "Startup Repair cannot repair this computer automatically"
5. select the view problem details (in the bottom left)
6. in the drop down click the last link to open a .txt file
7. now use Notepad to rename sethc and cmd
8. reboot computer into Windows 7
9. at login screen hit SHIFT key 5 times
10. this will bring up cmd
  - enter the following command to list all users on the system
```
> net user 
> net user "username" *
```
replace "username" with the users actual name.

enter the new password or leave blank for no password (press Enter)

reboot and login



## Other possible attack vectors 
- On-Screen Keyboard: C:\Windows\System32\osk.exe, launched when the  Windows + Ctrl + O key combination is pressed
- Magnifier: C:\Windows\System32\Magnify.exe, launched when the Windows logo key + Plus sign (+) key combination is pressed
- Narrator: C:\Windows\System32\Narrator.exe, launched when the Windows logo key + Ctrl + Enter key combination is pressed 
- Display Switcher: C:\Windows\System32\DisplaySwitch.exe, launched when the hold down the left CTRL key + left Windows Key, and use the left and right arrow keys combination is pressed
- App Switcher: C:\Windows\System32\AtBroker.exe, launched when the Alt + Tab key combination is pressed
- Utilman: C:\Windows\System32\utilman.exe, launched when the Windows + U key combination is pressed




## References:
https://attack.mitre.org/techniques/T1546/008/
