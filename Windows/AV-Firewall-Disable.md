# Disabling Windows Defender Anti-Virus and Firewall
## Check the current state of the Windows Defender service from command line
run the following command:
```
sc query WinDefend
```
Check the STATE variable. It should be in RUNNING state if it is enabled.

## Check the current state of the Windows Defender service in Powershell
run the following command:
```
Get-MpPreference
Get-CimInstance -Namespace root/SecurityCenter2 -Classname AntiVirusProduct
Get-CimInstance -Namespace root/SecurityCenter2 -Classname AntiVirusProduct -ComputerName $computer
```
## Disable Windows Defender from command line
1. Open command prompt with administrative privileges
2. Run the following command:
```
sc stop WinDefend
```

## Disable Windows Defender permanently from command line
run the following command:
```
sc config WinDefend start= disabled
sc stop WinDefend
```

## Check the current state of the Windows Defender service
run the following command:
```
sc query WinDefend
```
Check the STATE variable. It should be in RUNNING state if it is enabled.

## Permanently Disable Windows Defender Using PowerShell
1. Run PowerShell with administrative privileges (Windows key + X + A)
2. run the following command:
```
Set-MpPreference -DisableRealtimeMonitoring $true
```

## Permanently Turn Off Windows Defender Using Group Policy
1. Open Group Policy Editor (Run –> gpedit.msc)
2. Go to Computer Configuration –> Administrative Templates –> Windows Components –> Windows Defender Antivirus
3. From the right-hand pane, open Turn off Windows Defender Antivirus and select Enabled
This setting can be accessed through Local Group Policy as well as Domain Group Policy. The local policy will turn off Windows Defender for all local users while the domain policy will disable it for all systems on which the policy is applied

## Permanently Disable Windows Defender Using Windows Registry
1. Go to Run –> regedit. This will open the Windows Registry Editor.
2. Navigate to the following key:
```
HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows Defender
```
3. In the right pane, right-click the empty area and create a new DWORD (32-bit) value.
4. Rename the new item to DisableAntiSpyware
5. Double-click DisableAntiSpyware and change its value to 1.
Windows Defender will not load after the next computer restart. 

## Turn off Windows Firewall only
To turn off Windows Firewall only and keep using other Windows Defender functionality, follow the steps below:
1. Open Windows Settings (Windows key + i)
2. Click on Update & Security and then Windows Security
3. In the right-hand pane, click on Open Windows Security
4. From the left-hand pane, select Firewall & network protection
5. In the right-hand pane, you will see three protection types. Domain network, Private network, Public network.
6. Click on each network type and toggle it to disabled.
This will only turn off the firewall. The antivirus and other functionality of Windows Defender will keep on working.

## Turn off Windows Defender real-time antivirus only
If you want to turn off the antivirus real-time functionality only, you can follow the steps below:
1. Open Windows Settings (Windows key + i)
2. Click on Update & Security and then Windows Security
3. From the left-hand pane, click on Virus & threat protection
4. right-hand pane, toggle real-time protection to off.
  
## Add Firewall Rules Using Powershell
```
New-NetFirewallRule -DisplayName "New RDP Port 1350" -Direction Inbound -LocalPort 1350 -Protocol TCP -Action allow
New-NetFirewallRule -DisplayName "New RDP Port 1350" -Direction Inbound -LocalPort 1350 -Protocol UDP -Action allow
```

## Add to Registry New Port Using Powershell
```
Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" -Name PortNumber -Value 1350
```

## Defender Path/File/Extension Exclusion
https://docs.microsoft.com/en-us/powershell/module/defender/add-mppreference?view=windowsserver2019-ps
```
powershell -inputformat none -outputformat none -NonInteractive -Command Add-MpPreference -ExclusionPath "C:\Windows\SysWOW64\Mpk"
powershell -Command Add-MpPreference -ExclusionPath "C:\tmp"
powershell -Command Add-MpPreference -ExclusionProcess "java.exe"
powershell -Command Add-MpPreference -ExclusionExtension ".java"
```

## Using Powershell to add exclusions
https://aavtech.site/2018/01/adding-exclusions-in-windows-defender/
```
# Add exclusions
# add a path to exclusion list
Add-MpPreference -ExclusionPath E:\CPP
# add a process to exclusion list
Add-MpPreference -ExclusionProcess "C:\Program Files (x86)\FindAndRunRobot\FindAndRunRobot.exe"
# add an extension to exclusion list
Add-MpPreference -ExclusionExtension ".jpg"

# Remove exclusions
# remove a path from exclusion list
Remove-MpPreference -ExclusionPath E:\CPP
# remove a process from exclusion list
Remove-MpPreference -ExclusionProcess "C:\Program Files (x86)\FindAndRunRobot\FindAndRunRobot.exe"
# remove an extension from exclusion list
Remove-MpPreference -ExclusionExtension ".jpg"

# Display exclusions
Get-MpPreference | Select-Object ExclusionProcess
Get-MpPreference | Select-Object ExclusionPath
Get-MpPreference | Select-Object ExclusionExtension
```

## Test if Exclusion is Working
To test an extension exclusion you could create the EICAR file with the excluded extension instead of txt extension or to test an exclusion for jpg files create an EICAR file with a jpg extension.
```
echo X5O!P%@AP[4\PZX54(P^^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H* > sample.txt
echo X5O!P%@AP[4\PZX54(P^^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H* > sample.jpg
```
