# Check for anti virus installed from CMD
```cmd
WMIC /Node:localhost /Namespace:\\root\SecurityCenter2 Path AntiVirusProduct Get displayName /Format:List
```
### output: 
```
Microsoft Windows [Version 10.0.19045.4046]
(c) Microsoft Corporation. All rights reserved.

C:\Users\test>WMIC /Node:localhost /Namespace:\\root\SecurityCenter2 Path AntiVirusProduct Get displayName /Format:List

displayName=Windows Defender
```


https://gist.github.com/jdhitsolutions/1b9dfb31fef91f34c54b344c6516c30b
# Check for anti virus installed from Powershell
```powershell
Get-CimInstance -Namespace root/SecurityCenter2 -ClassName AntivirusProduct
```
### output: 
```
PS C:\Users\test>
>> Get-CimInstance -Namespace root/SecurityCenter2 -ClassName AntivirusProduct

displayName              : Windows Defender
instanceGuid             : {D68DDC3A-831F-4fae-9E44-DA132C1ACF46}
pathToSignedProductExe   : windowsdefender://
pathToSignedReportingExe : %ProgramFiles%\Windows Defender\MsMpeng.exe
productState             : 397568
timestamp                : Mon, 04 Mar 2024 18:28:49 GMT
PSComputerName           :
```


https://janegilring.wordpress.com/2011/06/12/use-windows-powershell-to-get-antivirus-product-information/
```powershell
function Get-AntiVirusProduct {
[CmdletBinding()]
param (
[parameter(ValueFromPipeline=$true, ValueFromPipelineByPropertyName=$true)]
[Alias(‘name’)]
$computername=$env:computername
)
$AntiVirusProduct = Get-WmiObject -Namespace root\SecurityCenter2 -Class AntiVirusProduct  -ComputerName $computername

#Switch to determine the status of antivirus definitions and real-time protection.
#The values in this switch-statement are retrieved from the following website: http://community.kaseya.com/resources/m/knowexch/1020.aspx
switch ($AntiVirusProduct.productState) {
"262144" {$defstatus = "Up to date" ;$rtstatus = "Disabled"}
    "262160" {$defstatus = "Out of date" ;$rtstatus = "Disabled"}
    "266240" {$defstatus = "Up to date" ;$rtstatus = "Enabled"}
    "266256" {$defstatus = "Out of date" ;$rtstatus = "Enabled"}
    "393216" {$defstatus = "Up to date" ;$rtstatus = "Disabled"}
    "393232" {$defstatus = "Out of date" ;$rtstatus = "Disabled"}
    "393488" {$defstatus = "Out of date" ;$rtstatus = "Disabled"}
    "397312" {$defstatus = "Up to date" ;$rtstatus = "Enabled"}
    "397328" {$defstatus = "Out of date" ;$rtstatus = "Enabled"}
    "397584" {$defstatus = "Out of date" ;$rtstatus = "Enabled"}
default {$defstatus = "Unknown" ;$rtstatus = "Unknown"}
    }

#Create hash-table for each computer
$ht = @{}
$ht.Computername = $computername
$ht.Name = $AntiVirusProduct.displayName
$ht.ProductExecutable = $AntiVirusProduct.pathToSignedProductExe
$ht.‘Definition Status’ = $defstatus
$ht.‘Real-time Protection Status’ = $rtstatus

#Create a new object for each computer
New-Object -TypeName PSObject -Property $ht

}
```

