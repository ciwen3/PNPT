List of programs and commands to run from the command line to prove I have control over the system. 

1. calc.exe
2. explorer.exe
3. powershell.exe
4. taskmgr.exe


# CMD.exe
1. whoami
2. whoami /priv
3. netstat -ano
4. hostname
5. WMIC /NODE:"computername" COMPUTERSYSTEM GET USERNAME
6. wmic BIOS Get SerialNumber
7. wmic BaseBoard Get SerialNumber
8. wmic OS GET CAPTION,VERSION
9. wmic UserAccount WHERE Name="<USERNAME>" Get Name,SID
10. wmic PATH Win32_NetworkLoginProfile GET Name,LastLogon
11. wmic /node: xxx.xxx.xxx.xxx COMPUTERSYSTEM GET USERNAME

# Powershell PS1
1. $PSVersionTable.PSVersion
2. $host.Version
3. (Get-Host).Version
4. (Get-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\PowerShell\3\PowerShellEngine -Name 'PowerShellVersion').PowerShellVersion
5. reg query HKLM\SOFTWARE\Microsoft\PowerShell\3\PowerShellEngine /v PowerShellVersion
6. $PSVersionTable
7. $PSVersionTable.PSVersion
