# GUI Based Attacks
https://twitter.com/last0x00/status/1433494772421992456?s=12
## Spawn CMD with more privledges
1. open TaskManager
2. Go to the Performance Tab
3. Click Open Resource Monitor
4. In Resource Monitor click File 
5. Save Settings As...
6. File Explore will Open
7. In the Address Bar type: ``` cmd.exe ``` hit enter
8. When CMD opens type: ``` whoami /all ``` hit enter
9. You should see Mandatory Label\High Mandatory Level and more Privledges than you would have seen if you just opened CMD

This seems to give a few extra Privledges that I wouldn't get by opneing CMD as Administrator. Similar to https://github.com/ciwen3/OSCP/tree/master/Windows/drivers


























