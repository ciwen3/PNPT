# theHarvester: Automated OSINT Email Gathering
requires some apis setup. 
```
theHarvester -d <domain> -b all 
```

# NMAP: Network Scan
check network with ping sweep
```
sudo nmap -sn -oA PingScan 192.168.1.0/24
```
get just the IP addresses for further searches. 
```
awk '{ print $2 }' PingScan.gnmap | sed 's/Nmap//g' > up.txt
```
look for interesting things one might want to attack
```
sudo nmap -A -sV -sC -p T:21-25,53,80,110,135-139,389,443,445,465,993,995,1433,1434,3389,8000,8080 -oA TCPScan 192.168.1.0/24    
sudo nmap -A -sV -sC -sU -p U:53,135-139,1434 -oA UDPScan 192.168.1.0/24
```
look for interesting things one might want to attack from up.txt to save time
```
sudo nmap -A -sV -sC -p T:21-25,53,80,110,135-139,389,443,445,465,993,995,1433,1434,3389,8000,8080 -oA -iL up.txt
sudo nmap -A -sV -sC -sU -p U:53,135-139,1434 -oA UDPScan -iL up.txt
```

# Feroxbuster: Website File and Directory Discovery
grab everything. will need to be modified to work. 
```
feroxbuster -e -f -k -x js php ini inf jsp htm html json pdf txt xlsx docx svg axd -w /usr/share/wordlists/dirb/common.txt -u http://10.129.35.132/login.php 
```
More usable searches
```
feroxbuster -e -k -x js php htm html json txt-w /usr/share/wordlists/dirb/common.txt -u http://10.129.35.132/login.php 
feroxbuster -e -f -k -w /usr/share/wordlists/dirb/common.txt -u http://10.129.35.132
```

# AutoRecon
```
sudo python3 ./autorecon.py 192.168.1.1
```

# Nikto: Vulnerability Scanner
Hosts, ports and protocols may also be specified by using a full URL syntax, and it will be scanned:
```
nikto -h https://192.168.0.1:443/
```
There is no need to specify that port 443 is encrypted, as Nikto will first test regular HTTP and if that fails, HTTPS. If you are sure it is an SSL/TLS server, specifying -s (-ssl) very slightly will speed up the test (this is also useful for servers that respond HTTP on port 443 even though content is only served when encryption is used).
```
nikto -h 192.168.0.1 -p 443 -ssl
```
Nikto can scan multiple ports in the same scanning session. To test more than one port on the same host, specify the list of ports in the -p (-port) option. Ports can be specified as a range (i.e., 80-90), or as a comma-delimited list, (i.e., 80,88,90). This will scan the host on ports 80, 88 and 443.
```
nikto -h 192.168.0.1 -p 80,88,443 -C all
```

# WPscan
### Docker Cheat Sheet
Pull the Docker repository
```
docker pull wpscanteam/wpscan
```
Run WPScan and enumerate usernames
```
docker run -it --rm wpscanteam/wpscan --url https://target.tld/ --enumerate u
```
When using --output flag along with the WPScan Docker image, a bind mount must be used. Otherwise, the file is written inside the Docker container, which is then thrown away.
```
mkdir ~/docker-bind
docker run --rm --mount type=bind,source=$HOME/docker-bind,target=/output wpscanteam/wpscan:latest -o /output/wpscan-output.txt --url 'https://example.com'
```
The wpscan-output.txt file now exists on the host machine at ~/docker-bind/wpscan-output.txt.

Pass password list to Docker container
```
docker run -it --rm -v /Users/__macuser__/:/__containerdirectory__ wpscanteam/wpscan --url http://example..com/ --passwords /__containerdirectory__/passwords.txt
```
See: https://github.com/wpscanteam/wpscan/issues/1256#issuecomment-609055053


### Cheat Sheet
Here we have put together a bunch of common commands that will help you get started quickly.

NOTE: Get your API token from wpscan.com if you also want the vulnerabilities associated with the detected plugin displaying.

Enumerate all plugins with known vulnerabilities
```
wpscan --url example.com -e vp --plugins-detection mixed --api-token YOUR_TOKEN
```
Enumerate all plugins in our database (could take a very long time)
```
wpscan --url example.com -e ap --plugins-detection mixed --api-token YOUR_TOKEN
```
Password brute force attack
```
wpscan --url example.com -e u --passwords /path/to/password_file.txt
```
The remote website is up, but does not seem to be running WordPress
If you get the Scan Aborted: The remote website is up, but does not seem to be running WordPress. error, it means that for some reason WPScan did not think that the site you are trying to scan is actually WordPress. If you think WPScan is wrong, you can supply the --force option to force WPScan to scan the site regardless. You may also need to set other options in this case, such as --wp-content-dir and --wp-plugins-dir.

Redirects
By default WPScan will follow in scope redirects, unless the --ignore-main-redirect option is given.


# SQLmap
1. https://hackertarget.com/sqlmap-post-request-injection/
2. https://sqlmap.org/
```
python sqlmap.py -u 'http://mytestsite.com/page.php?id=5'
```
## Getting blocked by the Web Application Firewall - WAF

Try using a different user agent then the default sqlmap with the --randomagent parameter.
```
python sqlmap.py -u "http://mytestsite.com/page.php?id=5" --random-agent
```
## Retrieve the Database Tables
```
python sqlmap.py -u 'http://mytestsite.com/page.php?id=5' --tables
```
## Dump the data

To get data we simply extend our command. Adding -T users will focus in on the users table where we might be able to get some credentials. Adding --dump will tell SQLmap to grab all the data from the users table, first the columns will be enumerated and then the data will be dumped from the columns.


## DB Connection strings:
### MySQL, Oracle, Microsoft SQL Server, PostgreSQL
```
DBMS://USER:PASSWORD@DBMS_IP:DBMS_PORT/DATABASE_NAME
```
### SQLite, Microsoft Access
```
DBMS://DATABASE_FILEPATH
```




















