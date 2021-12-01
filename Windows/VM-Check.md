https://www.ptsecurity.com/ww-en/analytics/antisandbox-techniques/

# Check if at least 15 processes are running.
### Powershell: 
```
 Get-Process | Measure-Object -line
```
### CMD:
```
tasklist
tasklist | find /v "" /c
```
### WMI
```
wmic process
wmic process list
```

# Checks if VMware Tools are running 
by searching for processes named "vmtoolsd" and "vbox.exe" in the list of active processes.
### Powershell: 
```
 Get-Process vmtoolsd, vbox
```
Anything except error messages means one of them is running 
```
 Get-Process vmtoolsd, vbox | Measure-Object -line
```
if out put is above 0 then one of them is running 

### CMD:
```
tasklist /fi "MODULES eq vmtoolsd"
tasklist /fi "MODULES eq vbox"
```

# Check Temperature
### Powershell:
```
$data = Get-WMIObject -Query "SELECT * FROM Win32_PerfFormattedData_Counters_ThermalZoneInformation" -Namespace "root/CIMV2"
@($data)[0].HighPrecisionTemperature
```
will return the temperature of the first CPU if it is not a Virtual Machine. 
### CMD:
```
wmic /namespace:\\root\WMI path MSAcpi_ThermalZoneTemperature get CurrentTemperature
```
if it returns an error it is a VM. otherwise it will return the CurrentTemperature.

# Check Fan Speed
### Powershell: 
```
$q = "select * from Win32_Fan"
Get-wmiobject -Query $q
```
if the response is empty it is a Virtual Machine.

# Registry key values checks
1. checks registry key values in System\CurrentControlSet\Enum\IDE and System\CurrentControlSet\Enum\SCSI to search for substrings that match QEMU, VirtualBox, VMware, or Xen virtualization
```
need to create
```

2. verifies that HKLM\SOFTWARE\Microsoft\Cryptography\MachineGuid does not equal "6ba1d002-21ed-4dbe-afb5-08cf8b81ca32"; HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\DigitalProductId does not equal "55274-649-6478953-23109", "A22-00001", or "47220", and that HARDWARE\Description\System\SystemBiosDate does not contain "01/02/03".
```
need to create
```

3. checks the registry key values in SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall for security products to avoid.
```
need to create
```

# File/Folder Checks
checks for the following files and directories on C:\ and D:\ drives:
```
cuckoo,
fake_drive,
perl,
strawberry,
targets.xls,
tsl,
wget.exe,
*python*.
```
The existence of any of these files or directories indicates that the malware is running in a sandbox or a code analyzer.


```
C:\Program Files\VMware\VMware Tools\vmtoolsd.exe exists and whether the following code analyzer and debugger DLLs have been loaded:

SbieDll.dll,
Dbghelp.dll,
Api_log.dll,
Dir_watch.dll.
```

# Check Hard drive Sizes
sandboxes have hard drives of less than 62 GB are assumed to be Virtual Machines

# detects a debugger in the system 

# other debugger checks
calls NtQuerySystemTime, GetSystemTimeAsFileTime, and GetTickCount. It calls each function twice to calculate a delta and performs a sleep operation between the first and second calls. If any of the three deltas is below 998 milliseconds, execution will terminate.


# Check Number of CPUs running
### Powershell:
```
(Get-CimInstance Win32_ComputerSystem).NumberOfLogicalProcessors
(Get-CimInstance -ClassName Win32_ComputerSystem).NumberOfLogicalProcessors
(Get-CimInstance -ClassName Win32_Processor | Measure-Object -Property NumberOfCores -Sum).Sum
(Get-CimInstance -ClassName Win32_Processor | Measure-Object -Property NumberOfLogicalProcessors -Sum).Sum
```
```
Get-WmiObject -Class Win32_Processor | Select-Object -Property Name, Number*
```
```
$processor = Get-ComputerInfo -Property CsProcessors
$processor.CsProcessors
```
### CMD:
```
echo %NUMBER_OF_PROCESSORS%
```
### WMI:
```
wmic cpu get NumberOfCores /value
wmic cpu get NumberOfCores,NumberOfLogicalProcessors
```

