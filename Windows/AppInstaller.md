Install application that gets full admin access and when it asks where to install the files choose browse > Shift + Right Click > open Powershell here
```
whoami
```
looking for NT/System

this can be setup by adding the following registry keys
```
REG ADD HKEY_CLASSES_ROOT\Directory\shell\powershellmenu /v "Open Power Shell Here" 
REG ADD HKEY_CLASSES_ROOT\Directory\shell\powershellmenu\command /v "C:\\Windows\\system32\\WindowsPowerShell\\v1.0\\powershell.exe -NoExit -Command Set-Location -LiteralPath '%L'"
```
