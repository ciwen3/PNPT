```
C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe -command $net_adapter=(Get-NetAdapter -IncludeHidden); 
$output= ($net_adapter); 
$output += ($net_adapter | fl *); 
$output += (Get-NetAdapterAdvancedProperty | fl); 
$net_adapter_bindings=(Get-NetAdapterBinding -IncludeHidden); 
$output += ($net_adapter_bindings); 
$output += ($net_adapter_bindings | fl); 
$output += (Get-NetIpConfiguration -Detailed); 
$output += (Get-DnsClientNrptPolicy); 
$output += (Resolve-DnsName bing.com); 
$output += (ping bing.com -4); 
$output += (ping bing.com -6); 
$output += (Test-NetConnection bing.com -InformationLevel Detailed); 
$output += (Test-NetConnection bing.com -InformationLevel Detailed -CommonTCPPort HTTP); 
$output += (Get-NetRoute); $output += (Get-NetIPaddress); $output += (Get-NetLbfoTeam); 
$output += (Get-Service -Name:VMMS); 
$output += (Get-VMSwitch); 
$output += (Get-VMNetworkAdapter -all); 
$output += (Get-DnsClientNrptPolicy); 
$output += (Get-WindowsOptionalFeature -Online); 
$output += (Get-Service | fl); 
$pnp_devices = (Get-PnpDevice); 
$output += ($pnp_devices); 
$output += ($pnp_devices | Get-PnpDeviceProperty -KeyName DEVPKEY_Device_InstanceId,DEVPKEY_Device_DevNodeStatus,DEVPKEY_Device_ProblemCode); 
$output | Out-File config\PowershellInfo.log
```
```
powershell -command 'Get-DhcpServerInDC'
```
```
powershell.exe -NoProfile -WindowStyle Hidden -NonInteractive -Command Register-ScheduledTask -Force -TaskName 'npcapwatchdog' -Description 'Ensure Npcap service is configured to start at boot' -Action (New-ScheduledTaskAction -Execute 'C:\Program Files\Npcap\CheckStatus.bat') -Principal (New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount) -Trigger (New-ScheduledTaskTrigger -AtStartup)
```

































