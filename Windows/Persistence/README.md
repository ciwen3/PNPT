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
# WIndows Persistance Techniques
## ElevetedScheduleTask:
- https://www.windowstricks.in/2018/08/how-to-run-the-powershell-script-in-scheduled-task-with-run-as-administrator.html
- https://stackoverflow.com/questions/62245797/how-to-setup-a-powershell-script-in-windows-task-scheduler-with-admin-permission
- https://superuser.com/questions/1640613/how-to-run-a-powershell-script-with-elevated-access-using-task-scheduler
- https://blog.netwrix.com/2018/07/03/how-to-automate-powershell-scripts-with-task-scheduler/
- https://www.reddit.com/r/PowerShell/comments/6qvp30/task_schedule_powershell_script_with_admin_rights/
- https://o365reports.com/2019/08/02/schedule-powershell-script-task-scheduler/
- https://pentestlab.blog/2019/11/04/persistence-scheduled-tasks/
- https://www.elastic.co/guide/en/security/current/persistence-via-telemetrycontroller-scheduled-task-hijack.html
- https://attack.mitre.org/techniques/T1053/005/

## Multiaction Task:
- https://securitybyexpert.com/windows-persistence-multi-action-scheduled-task/
- https://www.fireeye.com/blog/threat-research/2019/09/sharpersist-windows-persistence-toolkit.html
- https://www.igi-global.com/dictionary/assessment-of-task-persistence/50930
- https://techdocs.broadcom.com/us/en/symantec-security-software/identity-security/identity-manager/14-4/configuring/task-persistence.html
- https://www.elastic.co/guide/en/security/7.x/persistence-via-telemetrycontroller-scheduled-task-hijack.html

## WMI Event Subscription:
- https://pentestlab.blog/2020/01/21/persistence-wmi-event-subscription/
- https://www.elastic.co/guide/en/security/current/persistence-via-wmi-event-subscription.html
- https://medium.com/threatpunter/detecting-removing-wmi-persistence-60ccbb7dff96
- https://www.mdsec.co.uk/2019/05/persistence-the-continued-or-prolonged-existence-of-something-part-3-wmi-event-subscription/
- https://in.security/an-intro-into-abusing-and-identifying-wmi-event-subscriptions-for-persistence/
- https://liberty-shell.com/sec/2019/06/16/wmi-persistence/
- https://techcommunity.microsoft.com/t5/microsoft-defender-for-endpoint/asr-in-intune-for-quot-block-persistence-through-wmi-event/m-p/2068130
- https://microsoftintune.uservoice.com/forums/291681-ideas/suggestions/40862476-asr-rule-block-persistence-through-wmi-event-subs
- https://www.rapid7.com/db/modules/exploit/windows/local/wmi_persistence/

## App cert DLLS: 
- https://www.elastic.co/guide/en/security/current/registry-persistence-via-appcert-dll.html
- https://attack.mitre.org/techniques/T1546/009/
- https://pentestlab.blog/2020/01/07/persistence-appinit-dlls/
- https://eqllib.readthedocs.io/en/latest/analytics/14f90406-10a0-4d36-a672-31cabe149f2f.html
- https://github.com/ewilded/Windows_persistence/blob/master/REGISTRY.md
- https://dmfrsecurity.com/2021/01/02/review-red-team-operator-windows-persistence-course-by-sektor7-institute/

## App init DLLS:
- https://eforensicsmag.com/appinit-dll-injection-by-siddharth-sharma/
- https://attack.mitre.org/techniques/T1546/010/
- https://www.elastic.co/guide/en/security/current/registry-persistence-via-appinit-dll.html
- https://eqllib.readthedocs.io/en/latest/analytics/822dc4c5-b355-4df8-bd37-29c458997b8f.html
- https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1546.010/T1546.010.md
- https://github.com/akapv/atomic-red-team/blob/master/Windows/Persistence/AppInit_DLLs.md
- https://docs.microsoft.com/en-us/windows/win32/dlls/secure-boot-and-appinit-dlls
- https://www.cyberhuntingguide.net/t1546010.htmlNetshHelperDLL
- https://pentestlab.blog/2019/10/29/persistence-netsh-helper-dll/
- https://attack.mitre.org/techniques/T1546/007/
- https://www.ired.team/offensive-security/persistence/t1128-netsh-helper-dll
- https://github.com/rtcrowley/Offensive-Netsh-Helper
- https://dmcxblue.gitbook.io/red-team-notes-2-0/red-team-techniques/persistence/t1546-event-triggered-execution/netsh-helper-dll
- https://www.hackingarticles.in/windows-persistence-using-netsh/
- https://www.reddit.com/r/netsec/comments/donwj5/persistence_netsh_helper_dll/
- https://liberty-shell.com/sec/2018/07/28/netshlep/
- https://eqllib.readthedocs.io/en/latest/analytics/5f9a71f4-f5ef-4d35-aff8-f67d63d3c896.html

## Time Provider Persistence:
- https://www.ired.team/offensive-security/persistence/t1209-hijacking-time-providers
- https://pentestlab.blog/2019/10/22/persistence-time-providers/
- https://attack.mitre.org/techniques/T1547/003/
- https://github.com/elastic/detection-rules/issues/853
- https://github.com/endgameinc/eqllib/blob/master/eqllib/analytics/persistence/T1209-persistence-time-providers.toml
- https://institute.sektor7.net/rto-windows-persistence
- https://medium.com/@gabriel.pirjolescu/demystifying-windows-malware-hunting-part-1-detecting-persistence-with-osquery-b53573c2aac0

## Port Monitors:
- https://pentestlab.blog/2019/10/28/persistence-port-monitors/#https:~https:text=Interaction%20with%20the%20service%20is,configuration%2C%20data%20and%20monitor%20files.
- https://www.hackingarticles.in/windows-persistence-port-monitors/
- https://posts.slayerlabs.com/monitor-persistence/
- https://github.com/airzero24/PortMonitorPersist
- https://www.ired.team/offensive-security/persistence/t1013-addmonitor
- https://windows-internals.com/printdemon-cve-2020-1048/lsa-as-a-persistence
- https://adsecurity.org/?p=1760
- https://attack.mitre.org/tactics/TA0003/
- https://pentestlab.blog/2019/10/21/persistence-security-support-provider/
- https://www.elastic.co/guide/en/security/current/potential-lsa-authentication-package-abuse.html
- https://lifars.com/2021/01/common-malware-persistence-techniques/
- https://www.csoonline.com/article/3393268/how-to-outwit-attackers-using-two-windows-registry-settings.html
- https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2012-r2-and-2012/hh994565(v=ws.11)
- https://www.ndss-symposium.org/wp-content/uploads/2017/09/P01_3.pdf

## Metasploit Persistence:
- https://www.hackingarticles.in/multiple-ways-to-persistence-on-windows-10-with-metasploit/
- https://www.offensive-security.com/metasploit-unleashed/meterpreter-service/
- https://www.offensive-security.com/metasploit-unleashed/persistent-backdoors/
- https://www.hackers-arise.com/how-to-make-the-meterpreter-persistent
- https://securityonline.info/automated-persistent-backdoor-metasploit/
- https://secnhack.in/technique-to-persistence-on-windows-10-with-metasploit/
- https://pentestlab.blog/2020/02/04/persistence-waitfor/
- https://www.rapid7.com/db/modules/exploit/windows/local/persistence/
- https://ways2hack.com/metasploit-framework/
