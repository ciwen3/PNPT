# KQL for Azure Sentinel database searches
## Use KQL to grab useful information for hacking
Taken from: https://www.youtube.com/watch?v=DuWBLsgqhaI

look for systems running for long time, which means they haven't been rebooted in a long time. which means they are less likely to have patches installed. 

## Kusto Query Language (KQL)
```
Perf
| Where ObjectName == "System"
| Where CounterName == "Sytem UP Time" or CounterName == "Uptime"
| extend UpTime = CounterValue * 1s
| project TimeGenerated , Computer , UpTime , InstanceName
| summarize arg_max(TimeGenerated, *) by Computer
| order by UpTime desc
```

## Explination:
```
Perf                                                                  <== Performance info from Azure Monitor 
| Where ObjectName == "System"                                        <== System performace counters
| Where CounterName == "Sytem UP Time" or CounterName == "Uptime"     <== Uptime counters for Windows and Linux 
| extend UpTime = CounterValue * 1s                                   <== change counter value from milliseconds to seconds
| project TimeGenerated , Computer , UpTime , InstanceName            <== show (project) these info fields
| summarize arg_max(TimeGenerated, *) by Computer                     <== create table 
| order by UpTime desc                                                <== put the table in descending order based on the Uptime
``` 



