
# Reversing PowerShell Commands: 
https://twitter.com/pmelson/status/1263510602305146882

When we replace 'IEX' with 'Write-Host' and run the script this time, we get human-readable code that is the final payload. There are a few ways in PowerShell to call for execution (Invoke-Expression, IEX, Invoke-Command, ICM, .invoke(), setting an alias, etc.)
