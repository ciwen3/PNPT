cd "C:\Program files (x86)\Sophos\Sophos Home"
SophosUI.exe /unlock
net stop "Sophos Anti-Virus"
net stop "Sophos AutoUpdate Service"
"C:\program files\Sophos\Sophos Endpoint Agent\uninstallcli.exe"

:Sophos AutoUpdate
MsiExec.exe /qn /X{72E136F7-3751-422E-AC7A-1B2E46391909} REBOOT=ReallySuppress

:SOPHOS HOME 
MsiExec.exe /qn /X{2519A41E-5D7C-429B-B2DB-1E943927CB3D} REBOOT=ReallySuppress /L*v %windir%\Temp\Uninstall_SophosHome_Log.txt
MsiExec.exe /qn /X{2C14E1A2-C4EB-466E-8374-81286D723D3A} REBOOT=ReallySuppress /L*v %windir%\Temp\Uninstall_SophosHome1_Log.txt
MsiExec.exe /qn /X{4627F5A1-E85A-4394-9DB3-875DF83AF6C2} REBOOT=ReallySuppress /L*v %windir%\Temp\Uninstall_SophosHome2_Log.txt
MsiExec.exe /qn /I{60EC980A-BDA2-4CB6-A427-B07A5498B4CA} REBOOT=ReallySuppress /L*v %windir%\Temp\Uninstall_SophosHome3_Log.txt
MsiExec.exe /qn /X646A3744-5295-487E-9246-47D35FA535FC} REBOOT=ReallySuppress /L*v %windir%\Temp\Uninstall_SophosHome4_Log.txt
MsiExec.exe /qn /X{AD51DA75-7BD1-4345-BE48-68ACBA01171C} REBOOT=ReallySuppress /L*v %windir%\Temp\Uninstall_SophosHome5_Log.txt
MsiExec.exe /qn /X{AFBCA1B9-496C-4AE6-98AE-3EA1CFF65C54} REBOOT=ReallySuppress /L*v %windir%\Temp\Uninstall_SophosHome6_Log.txt
MsiExec.exe /qn /I{F57566D7-8CEF-447D-A7D0-7418E536FA21} REBOOT=ReallySuppress /L*v %windir%\Temp\Uninstall_SophosHome7_Log.txt
MsiExec.exe /qn /X{7CD26A0C-9B59-4E84-B5EE-B386B2F7AA16} REBOOT=ReallySuppress
MsiExec.exe /qn /X{BCF53039-A7FC-4C79-A3E3-437AE28FD918} REBOOT=ReallySuppress
MsiExec.exe /qn /X{9D1B8594-5DD2-4CDC-A5BD-98E7E9D75520} REBOOT=ReallySuppress
MsiExec.exe /qn /X{E82DD0A8-0E5C-4D72-8DDE-41BB0FC06B3E} REBOOT=ReallySuppress
MsiExec.exe /qn /X{A7FCCD72-7481-4694-84EC-6A276406266F} REBOOT=ReallySuppress

:Sophos Anti-Virus (Endpoint)
MsiExec.exe /qn /X{8123193C-9000-4EEB-B28A-E74E779759FA} REBOOT=ReallySuppress
MsiExec.exe /qn /X{36333618-1CE1-4EF2-8FFD-7F17394891CE} REBOOT=ReallySuppress
MsiExec.exe /qn /X{DFDA2077-95D0-4C5F-ACE7-41DA16639255} REBOOT=ReallySuppress
MsiExec.exe /qn /X{CA3CE456-B2D9-4812-8C69-17D6980432EF} REBOOT=ReallySuppress
MsiExec.exe /qn /X{3B998572-90A5-4D61-9022-00B288DD755D} REBOOT=ReallySuppress
MsiExec.exe /qn /X{CBA26491-B602-484E-B846-00623CA80D03} REBOOT=ReallySuppress

:Sophos Anti-Virus (Server)
MsiExec.exe /qn /X{72E30858-FC95-4C87-A697-670081EBF065} REBOOT=ReallySuppress

:Sophos System Protection
MsiExec.exe /qn /X{934BEF80-B9D1-4A86-8B42-D8A6716A8D27} REBOOT=ReallySuppress
MsiExec.exe /qn /X{1093B57D-A613-47F3-90CF-0FD5C5DCFFE6} REBOOT=ReallySuppress

:Sophos Network Threat Protection
MsiExec.exe /qn /X{66967E5F-43E8-4402-87A4-04685EE5C2CB} REBOOT=ReallySuppress
MsiExec.exe /qn /X{604350BF-BE9A-4F79-B0EB-B1C22D889E2D} REBOOT=ReallySuppress

:Sophos Health
MsiExec.exe /qn /X{A5CCEEF1-B6A7-4EB4-A826-267996A62A9E} REBOOT=ReallySuppress
MsiExec.exe /qn /X{D5BC54B8-1DA1-44F4-AE6F-86E05CDB0B44} REBOOT=ReallySuppress
MsiExec.exe /qn /X{E44AF5E6-7D11-4BDF-BEA8-AA7AE5FE6745} REBOOT=ReallySuppress

:Sophos Management Communications System
MsiExec.exe /qn /X{A1DC5EF8-DD20-45E8-ABBD-F529A24D477B} REBOOT=ReallySuppress
MsiExec.exe /qn /X{1FFD3F20-5D24-4C9A-B9F6-A207A53CF179} REBOOT=ReallySuppress
MsiExec.exe /qn /X{D875F30C-B469-4998-9A08-FE145DD5DC1A} REBOOT=ReallySuppress
MsiExec.exe /qn /X{2C14E1A2-C4EB-466E-8374-81286D723D3A} REBOOT=ReallySuppress

:UI
MsiExec.exe /qn /X{D29542AE-287C-42E4-AB28-3858E13C1A3E} REBOOT=ReallySuppress

:SophosClean
"C:\Program Files\Sophos\Clean\uninstall.exe"

:SophosHomeClean
"C:\Program Files\Sophos\Home Clean\uninstall.exe"

:Machine Learning 
"C:\Program Files\Sophos\Sophos ML Engine\uninstall.exe"

:Standalone agent 
"C:\Program Files\Sophos\Sophos Standalone Engine\Uninstall.exe"

:SED
"C:\Program Files\Sophos\Endpoint Defense\uninstall.exe" /quiet

:HMPA 1.0.0.699
"C:\Program Files (x86)\HitmanPro.Alert\uninstall.exe" /uninstall /quiet

:HMPA (managed) 3.5.3.563
"C:\Program Files (x86)\HitmanPro.Alert\hmpalert.exe" /uninstall /quiet

:HMPA 3.7.14.265
"C:\Program Files\HitmanPro\HitmanPro.exe" /uninstall /quiet