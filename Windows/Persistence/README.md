# Create a Service:
```
sc create TestService binPath= "C:\service.exe" start= auto
sc start TestService
```

# Scheduled Task
```
schtasks /create /f /tn Backdoor /SC ONCE /ST 00:00 /TR "C:\shell.exe"
schtasks /run /tn Backdoor
```
