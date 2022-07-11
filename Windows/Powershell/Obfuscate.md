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
Adding white space that is removed when the code it ran. This won't affect its ability to run but will make it harder to read or pattern match. 
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
