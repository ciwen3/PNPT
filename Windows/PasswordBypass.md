# Windows 7 Circumvent the Password:
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
