This will search for any ASR rules that are configured and disable them. 
```Powershell
Get-MpPreference | select AttackSurfaceReductionRules_Ids, AttackSurfaceReductionRules_Actions | ForEach-Object -ProcessGet-MpPreference | select AttackSurfaceReductionRules_Ids, AttackSurfaceReductionRules_Actions | ForEach-Object -Process { Add-MpPreference -AttackSurfaceReductionRules_Ids $_.AttackSurfaceReductionRules_Ids -AttackSurfaceReductionRules_Actions Disabled }
```







Hunt for events
Use the following query for getting network protection events in Advanced Hunting:

```kql
DeviceEvents
| where ActionType == "ExploitGuardNetworkProtectionBlocked"
| extend ParsedFields=parse_json(AdditionalFields)
| project DeviceName, ActionType, Timestamp, RemoteUrl, InitiatingProcessFileName, ResponseCategory=tostring(ParsedFields.ResponseCategory)
| where ResponseCategory == "CustomPolicy"
Use the following query for getting SmartScreen events in Advanced Hunting:

DeviceEvents
| where ActionType == "SmartScreenUrlWarning"
| extend ParsedFields=parse_json(AdditionalFields)
| project DeviceName, ActionType, Timestamp, RemoteUrl, InitiatingProcessFileName, Experience=tostring(ParsedFields.Experience)
| where Experience == "CustomPolicy"

DeviceEvents
| where TimeGenerated >= ago(90d)
| where ActionType startswith 'Asr'

DeviceEvents
| where ActionType startswith "Asr"
| summarize ASRCount=count()by ActionType, InitiatingProcessCommandLine 
| sort by ActionType asc, ASRCount desc 

//Summary of each ASR rule:
DeviceEvents
 | where ActionType startswith "Asr" 
 | summarize NumberOfEvents=count() by ActionType
 | sort by NumberOfEvents desc


Use the following query for getting Controlled Folder audit/blocked events in Advanced Hunting:

DeviceEvents
| where ActionType in ('ControlledFolderAccessViolationAudited','ControlledFolderAccessViolationBlocked')
```

Attack surface reduction rules
Block abuse of exploited vulnerable signed drivers
Block credential stealing from the Windows local security authority subsystem (lsass.exe)

The values to enable (Block), disable, warn, or enable in audit mode are:

0: Disable (Disable the attack surface reduction rule)
1: Block (Enable the attack surface reduction rule)
2: Audit (Evaluate how the attack surface reduction rule would impact your organization if enabled)
6: Warn (Enable the attack surface reduction rule but allow the end-user to bypass the block). Warn mode is available for most of the attack surface reduction rules.


Powershell commands to enable ASR: 
Enable attack surface reduction rules 
```powershell
Set-MpPreference -AttackSurfaceReductionRules_Ids <rule ID> -AttackSurfaceReductionRules_Actions Enabled
```
Enable attack surface reduction rules in audit mode	
```powershell
Add-MpPreference -AttackSurfaceReductionRules_Ids <rule ID> -AttackSurfaceReductionRules_Actions AuditMode
```
Enable attack surface reduction rules in warn mode 
```powershell
Add-MpPreference -AttackSurfaceReductionRules_Ids <rule ID> -AttackSurfaceReductionRules_Actions Warn
```
Enable attack surface reduction Block abuse of exploited vulnerable signed drivers 
```powershell
Add-MpPreference -AttackSurfaceReductionRules_Ids 56a863a9-875e-4185-98a7-b882c64b5ce5 -AttackSurfaceReductionRules_Actions Enabled
```
Turn off attack surface reduction rules 
```powershell
Add-MpPreference -AttackSurfaceReductionRules_Ids <rule ID> -AttackSurfaceReductionRules_Actions Disabled
```


In the following example, the first two rules are enabled, the third rule is disabled, and the fourth rule is enabled in audit mode: Set-MpPreference -AttackSurfaceReductionRules_Ids <rule ID 1>,<rule ID 2>,<rule ID 3>,<rule ID 4> -AttackSurfaceReductionRules_Actions Enabled, Enabled, Disabled, AuditMode


 Warning
Set-MpPreference overwrites the existing set of rules. If you want to add to the existing set, use Add-MpPreference instead. You can obtain a list of rules and their current state by using Get-MpPreference.
To exclude files and folders from attack surface reduction rules, use the following cmdlet:
Add-MpPreference -AttackSurfaceReductionOnlyExclusions "<fully qualified path or resource>"
Continue to use Add-MpPreference -AttackSurfaceReductionOnlyExclusions to add more files and folders to the list.



get the current status of the ASR rules
```powershell
Get-MpPreference | select AttackSurfaceReductionRules_Ids, AttackSurfaceReductionRules_Actions
```


prevent Adobe Reader from starting child processes, use PowerShell as follows:

Set-MpPreference `
-AttackSurfaceReductionRules_Ids 7674ba52-37eb-4a4f-a9a1-f0f9a1619a2c `
-AttackSurfaceReductionRules_Actions Enabled
To define exclusions for directories and files, invoke Set-MpPreference as follows:

```powershell
Set-MpPreference -AttackSurfaceReductionOnlyExclusions "c:\windows"
```

You can then query the status of this property using the following command:
```powershell
Get-MpPreference | select AttackSurfaceReductionOnlyExclusions
```


Event ID	Description
5007	Event when settings are changed
1121	Event when rule fires in block mode
1122	Event when rule fires in audit mode


query the log entries with PowerShell:
```powershell
Get-WinEvent -LogName 'Microsoft-Windows-Windows Defender/Operational' | where {$_.ID -eq "5007" -or $_.ID -like "112?"}
```

https://4sysops.com/archives/configure-attack-surface-reduction-in-microsoft-defender-using-group-policy-or-powershell/
Block abuse of exploited vulnerable signed drivers	56a863a9-875e-4185-98a7-b882c64b5ce5
Block Adobe Reader from creating child processes	7674ba52-37eb-4a4f-a9a1-f0f9a1619a2c
Block all Office applications from creating child processes	d4f940ab-401b-4efc-aadc-ad5f3c50688a
Block credential stealing from the Windows local security authority subsystem (lsass.exe)	9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2
Block executable content from email client and webmail	be9ba2d9-53ea-4cdc-84e5-9b1eeee46550
Block executable files from running unless they meet a prevalence, age, or trusted list criterion	01443614-cd74-433a-b99e-2ecdc07bfc25
Block execution of potentially obfuscated scripts	5beb7efe-fd9a-4556-801d-275e5ffc04cc
Block JavaScript or VBScript from launching downloaded executable content	d3e037e1-3eb8-44c8-a917-57927947596d
Block Office applications from creating executable content	3b576869-a4ec-4529-8536-b80a7769e899
Block Office applications from injecting code into other processes	75668c1f-73b5-4cf0-bb93-3ecf5cb7cc84
Block Office communication application from creating child processes	26190899-1602-49e8-8b27-eb1d0a1ce869
Block persistence through WMI event subscription
* File and folder exclusions not supported	e6db77e5-3df2-4cf1-b95a-636979351e5b
Block process creations originating from PSExec and WMI commands	d1e49aac-8f56-4280-b9ba-993a6d77406c
Block untrusted and unsigned processes that run from USB	b2b3f03d-6a65-4f7b-a9c7-1c7ef74a9ba4
Block Win32 API calls from Office macros	92e97fa1-2edf-4476-bdd6-9dd0b4dddc7b
Use advanced protection against ransomware	c1db55ab-c21a-4637-bb3f-a12568109d35









Block process creations originating from PSExec and WMI commands
GUID: d1e49aac-8f56-4280-b9ba-993a6d77406c


Block credential stealing from the Windows local security authority subsystem
GUID: 9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2



































Configure Controlled folder access with PowerShell
The PowerShell cmdlet Set-MpPreference can be used for enabling Controlled folder access in Enabled or block mode.

Enabled mode (block)
```powershell
Set-MpPreference -EnableControlledFolderAccess Enabled
```
Audit mode
Set-MpPreference -EnableControlledFolderAccess AuditMode
