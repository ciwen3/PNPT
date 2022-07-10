
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
