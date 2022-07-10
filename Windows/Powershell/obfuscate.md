
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


