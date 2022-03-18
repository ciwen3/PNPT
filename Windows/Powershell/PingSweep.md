# Powershell Pingsweepers

## PS ping sweeper:
```
1..255 | % {echo "192.168.1.$_"; ping -n 1 -w 100 192.168.1.$_} | Select-String ttl
```
## PS command metrics:
```
Measure-Command {}
```
## PS parallel ping sweeper:
```
workflow ParallelSweep { foreach -parallel -throttlelimit 4 ($i in 1..255) {ping -n 1 -w 100 10.0.0.$i}}; ParallelSweep | Select-String ttl
```
## PS multi-subnet ping sweeper with OS Detection:
```
0..10 | % { $a = $_; 1..255 | % { $b = $_; ping -n 1 -w 10 "10.0.$a.$b" | select-string TTL | % { if ($_ -match "ms") { $ttl = $_.line.split('=')[2] -as [int]; if ($ttl -lt 65) { $os = "Linux" } ElseIf ($ttl -gt 64 -And $ttl -lt 129) { $os = "Windows" } else { $os = "Cisco"}; write-host "10.0.$a.$b OS: $os"; echo "10.0.$a.$b" >> scan_results.txt }}} }
```
## PS test egress filtering:
```
1..1024 | %{echo ((new-object Net.Sockets.TcpClient).Connect("allports.exposed",$_)) "Port $_ is open" } 2>$null
Because of object pipelining in PowerShell, implementing a simple ping sweep utility is quick and easy.
```
## PS ping sweeper:
```
1..255 | % {echo "192.168.1.$_"; ping -n 1 -w 100 192.168.1.$_} | Select-String ttl
```
### Command Breakdown
1. 1..255 - Produce a list of numbers from 1 to 255</pre>
2. | - Pass each number as an object into the loop
3. % - The % operator in PowerShell is an alias for foreach-object, and is used to start a loop. 
The loop executes the content between {} in sequence
4. echo "192.168.1.$_"; - Prints out the IP address. $_ is a variable that means current object. The current object relates to number (1..255) that the loop is currently on.
5. ping - Packet internet groper utility tests for ICMP connectivity between two nodes.
6. -n 1 - The number of pings to send manual set to stop after 1
7. -w 100 - Number of milliseconds to wait before timeout. 
This may need to be adjusted depending on the latency of the target environment 8. 192.168.1.$_ - The IP address to ping
9. | Select-String ttl - Pipe all output from the loop into Select-String. Filters all lines not having ttl in them.
