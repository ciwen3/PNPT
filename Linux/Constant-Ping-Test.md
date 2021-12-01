# Constant Ping Test

```
for i in {1..1000}; do ping -c 2 10.129.35.132 | grep "0% packet loss"; echo "sleep for 60 sec and try again"; sleep 60; done
```
replace the IP address with your targets IP address. this has been useful for hackthebox to prevent my target machine from going down while I do stuff. 
