Email Recon:
============
# search for public info on emails 
https://hunter.io/users/sign_in

# search through known breaches for usernames and passwords (for credential stuffing)
https://github.com/hmaverickadams/breach-parse
./breach-parse.sh @tesla.com tesla.txt
will create: 
tesla-master.txt
tesla-passwords.txt
tesla-users.txt

# theharvester
# -d is the target, -l is how many searches deep you want to go, -b search engine to use
# will return emails, domains, and ip addresses
theharvester -d tesla.com -l 500 -b google


Target Validation:
==================

# WHOIS enumeration
whois domain-name-here.com 

# NSLOOKUP

# DNSRecon


Finding Subdomains:
===================
# sublist3r
sudo apt install sublist3r
# -d for domain, -t threads
sublist3r -d tesla.com -t 100

# crt.sh website certificate finger printing
https://crt.sh use search bar
% = wildcard
Example: %.tesla.com will search *.tesla.com

# owasp amass (best tool for searching out sub domains)
lookup ono github

# tomnomnom httprobe tool can be used to verify the list of websites

# dig
# Perform DNS IP Lookup
dig a domain-name-here.com @nameserver 
# Perform MX Record Lookup
dig mx domain-name-here.com @nameserver
# Perform Zone Transfer with DIG
dig axfr domain-name-here.com @nameserver

# DNS Zone Transfers
# Windows DNS zone transfer
nslookup -> set type=any -> ls -d blah.com 
# Linux DNS zone transfer
dig axfr blah.com @ns1.blah.com

# googlefu
site:tesla.com 
site:tesla.com -www
#searches the site without the www part of the url
site:tesla.com filetype:docx
site:tesla.com filetype:pdf

nmap

bluto






fingerprinting:
===============
nmap 

netcat

# wappalyzer (firefox add-on)
# will return what was used to build the website. 

# https://builtwith.com
# will return what was used to build the website. 

# whatweb (command line tool built into kali)
whatweb https://tesla.com
# will return what was used to build the website. 






data breaches:
==============
HaveIBeenPwned

BreachParse

WeLeakInfo

