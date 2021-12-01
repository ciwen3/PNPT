# Feroxbuster
https://github.com/epi052/feroxbuster
```
./feroxbuster -r -d 0 -x php pdf txt ini js py pl htm html -u http://website.com 
./feroxbuster -r -d 0 -x php pdf txt ini js py pl htm html -u http://<IP-address>
```
-x: file types you want to search for. 


# Nikto:
nikto -C all <Target-Host>
```
nikto -Display 1234EP -o report.html -Format htm -Tuning 123bde -host 192.168.0.102
```

# burp suite:
burp suite 1 has a spder  built in
burp suite 2 has it a little hidden


# html2dic:
extract all words from an HTML page, generating a dictionary one word per line. 

```
./html2dic <file>
```

# gendict:
alphanumeric dictionary generator that generates an incremental wordlist from the specified pattern
```
gendict
Usage: gendict -type pattern
  type: -n numeric [0-9]
        -c character [a-z]
        -C uppercase character [A-Z]
        -h hexa [0-f]
        -a alfanumeric [0-9a-z]
        -s case sensitive alfanumeric [0-9a-zA-Z]
  pattern: Must be an ascii string in which every 'X' character wildcard
           will be replaced with the incremental value.

Example: gendict -n thisword_X
  thisword_0
  thisword_1
  [...]
  thisword_9
```

# dirb:

dirb <url_base> [<wordlist_file(s)>] [options]
```
dirb http://url.com/
dirb http://url.com/ /usr/share/wordlists/dirb/common.txt
dirb http://url.com/directory/ (Simple Test)
dirb http://url.com/ -X .html (Test files with '.html' extension)
dirb http://url.com/ /usr/share/dirb/wordlists/vulns/apache.txt (Test with apache.txt wordlist)
dirb https://secure_url.com/ (Simple Test with SSL)
```
 \<url_base\> : Base URL to scan. (Use -resume for session resuming)
 \<wordlist_file(s)\> : List of wordfiles. (wordfile1,wordfile2,wordfile3...)

## HOTKEYS 
 'n' -> Go to next directory.
 'q' -> Stop scan. (Saving state for resume)
 'r' -> Remaining scan stats.

## OPTIONS 
 -a \<agent_string\> : Specify your custom USER_AGENT.
 -c \<cookie_string\> : Set a cookie for the HTTP request.
 -f : Fine tunning of NOT_FOUND (404) detection.
 -H \<header_string\> : Add a custom header to the HTTP request.
 -i : Use case-insensitive search.
 -l : Print "Location" header when found.
 -N \<nf_code\>: Ignore responses with this HTTP code.
 -o \<output_file\> : Save output to disk.
 -p \<proxy[:port]\> : Use this proxy. (Default port is 1080)
 -P \<proxy_username:proxy_password\> : Proxy Authentication.
 -r : Don't search recursively.
 -R : Interactive recursion. (Asks for each directory)
 -S : Silent Mode. Don't show tested words. (For dumb terminals)
 -t : Don't force an ending '/' on URLs.
 -u <username:password> : HTTP Authentication.
 -v : Show also NOT_FOUND pages.
 -w : Don't stop on WARNING messages.
 -X \<extensions\> / -x \<exts_file\> : Append each word with this extensions.
 -z \<milisecs\> : Add a miliseconds delay to not cause excessive Flood.



# dirbuster (GUI Tool):
#### extensions:
php,ini,htm,html,txt,py


# gobuster:

Scan a url (-u http://192.168.0.155/) for directories 

using a wordlist (-w /usr/share/wordlists/dirb/common.txt) 

print the full URLs of discovered paths (-e)
```
gobuster -e -u http://192.168.0.155/ -w /usr/share/wordlists/dirb/common.txt
```
### extensions
```
gobuster -x php,ini,htm,html,txt,py
```
### Wordlist Usage
```
gobuster -w <wordlist.txt>
```
### URL Usage
```
gobuster -u <url>
```

### Export option
```
gobuster -o <filename>
```
### Common Command line options
-fw – force processing of a domain with wildcard results.
-np – hide the progress output.
-m  – which mode to use, either dir or dns (default: dir).
-q – disables banner/underline output.
-t – number of threads to run (default: 10).
-u  – full URL (including scheme), or base domain name.
-v – verbose output (show all results).
-w  – path to the wordlist used for brute forcing (use – for stdin).

### Command line options for dns mode
-cn – show CNAME records (cannot be used with ‘-i’ option).
-i – show all IP addresses for the result.

### Command line options for dir mode
-a <user agent string> – specify a user agent string to send in the request header.
-c <http cookies> – use this to specify any cookies that you might need (simulating auth).
-e – specify extended mode that renders the full URL.
-f – append / for directory brute forces.
-k – Skip verification of SSL certificates.
-l – show the length of the response.
-n – “no status” mode, disables the output of the result’s status code.
-o <file> – specify a file name to write the output to.
-p <proxy url> – specify a proxy to use for all requests (scheme much match the URL scheme).
-r – follow redirects.
-s <status codes> – comma-separated set of the list of status codes to be deemed a “positive” (default: 200,204,301,302,307).
-x <extensions> – list of extensions to check for, if any.
-P <password> – HTTP Authorization password (Basic Auth only, prompted if missing).
-U <username> – HTTP Authorization username (Basic Auth only).
-to <timeout> – HTTP timeout. Examples: 10s, 100ms, 1m (default: 10s).



# wfuzz:
```
wfuzz [options] -z payload,params <url>
```
FUZZ, ..., FUZnZ  wherever you put these keywords wfuzz will replace them with the values of the specified payload.FUZZ{baseline_value} FUZZ will be replaced by baseline_value. It will be the first request performed and could be used as a base for filtering.

```
Options:
    -h/--help           : This help
    --help              : Advanced help
    --version           : Wfuzz version details
    -e <type>           : List of available encoders/payloads/iterators/printers/scripts
   
    --recipe <filename>     : Reads options from a recipe
    --dump-recipe <filename>    : Prints current options as a recipe
    --oF <filename>         : Saves fuzz results to a file. These can be consumed later using the wfuzz payload.
   
    -c              : Output with colors
    -v              : Verbose information.
    -f filename,printer         : Store results in the output file using the specified printer (raw printer if omitted).
    -o printer                  : Show results using the specified printer.
    --interact          : (beta) If selected,all key presses are captured. This allows you to interact with the program.
    --dry-run           : Print the results of applying the requests without actually making any HTTP request.
    --prev              : Print the previous HTTP requests (only when using payloads generating fuzzresults)
   
    -p addr             : Use Proxy in format ip:port:type. Repeat option for using various proxies.
                      Where type could be SOCKS4,SOCKS5 or HTTP if omitted.
   
    -t N                : Specify the number of concurrent connections (10 default)
    -s N                : Specify time delay between requests (0 default)
    -R depth            : Recursive path discovery being depth the maximum recursion level.
    -L,--follow         : Follow HTTP redirections
    -Z              : Scan mode (Connection errors will be ignored).
    --req-delay N           : Sets the maximum time in seconds the request is allowed to take (CURLOPT_TIMEOUT). Default 90.
    --conn-delay N              : Sets the maximum time in seconds the connection phase to the server to take (CURLOPT_CONNECTTIMEOUT). Default 90.
   
    -A              : Alias for --script=default -v -c
    --script=           : Equivalent to --script=default
    --script=<plugins>      : Runs script's scan. <plugins> is a comma separated list of plugin-files or plugin-categories
    --script-help=<plugins>     : Show help about scripts.
    --script-args n1=v1,...     : Provide arguments to scripts. ie. --script-args grep.regex="<A href="(.*?)">"
   
    -u url                      : Specify a URL for the request.
    -m iterator         : Specify an iterator for combining payloads (product by default)
    -z payload          : Specify a payload for each FUZZ keyword used in the form of name[,parameter][,encoder].
                      A list of encoders can be used, ie. md5-sha1. Encoders can be chained, ie. md5@sha1.
                      Encoders category can be used. ie. url
                                  Use help as a payload to show payload plugin's details (you can filter using --slice)
    --zP <params>           : Arguments for the specified payload (it must be preceded by -z or -w).
    --slice <filter>        : Filter payload's elements using the specified expression. It must be preceded by -z.
    -w wordlist         : Specify a wordlist file (alias for -z file,wordlist).
    -V alltype          : All parameters bruteforcing (allvars and allpost). No need for FUZZ keyword.
    -X method           : Specify an HTTP method for the request, ie. HEAD or FUZZ
   
    -b cookie           : Specify a cookie for the requests. Repeat option for various cookies.
    -d postdata             : Use post data (ex: "id=FUZZ&catalogue=1")
    -H header           : Use header (ex:"Cookie:id=1312321&user=FUZZ"). Repeat option for various headers.
    --basic/ntlm/digest auth    : in format "user:pass" or "FUZZ:FUZZ" or "domain\FUZ2Z:FUZZ"
   
    --hc/hl/hw/hh N[,N]+        : Hide responses with the specified code/lines/words/chars (Use BBB for taking values from baseline)
    --sc/sl/sw/sh N[,N]+        : Show responses with the specified code/lines/words/chars (Use BBB for taking values from baseline)
    --ss/hs regex           : Show/hide responses with the specified regex within the content
    --filter <filter>       : Show/hide responses using the specified filter expression (Use BBB for taking values from baseline)
    --prefilter <filter>        : Filter items before fuzzing using the specified expression.
```

### wfuzz Usage Example:
### Use colour output (-c), a wordlist as a payload (-z file,/usr/share/wfuzz/wordlist/general/common.txt), and hide 404 messages (–hc 404) to fuzz the given URL (http://192.168.1.202/FUZZ):
```
wfuzz -c -z file,/usr/share/wfuzz/wordlist/general/common.txt --hc 404 http://192.168.1.202/FUZZ
```

### Search for Folders using common.txt wordlist
```
wfuzz -w wordlist/general/common.txt http://testphp.vulnweb.com/FUZZ
```

### Search for php Files using common.txt wordlist
```
wfuzz -w wordlist/general/common.txt http://testphp.vulnweb.com/FUZZ.php
```

### Fuzzing Parameters In URLs
```
wfuzz -z range,0-10 --hl 97 http://testphp.vulnweb.com/listproducts.php?cat=FUZZ
```

### Fuzzing POST Requests
```
wfuzz -z file,wordlist/others/common_pass.txt -d "uname=FUZZ&pass=FUZZ"  --hc 302 http://testphp.vulnweb.com/userinfo.php
```

### Fuzz some form-encoded data like an HTML form, simply pass a -d command line argument
```
wfuzz -z file,wordlist/others/common_pass.txt -d "uname=FUZZ&pass=FUZZ"  --hc 302 http://testphp.vulnweb.com/userinfo.php
```

### Fuzzing Cookies
```
wfuzz -z file,wordlist/general/common.txt -b cookie=FUZZ http://testphp.vulnweb.com/
wfuzz -z file,wordlist/general/common.txt -b cookie=value1 -b cookie2=value2 http://testphp.vulnweb.com/FUZZ
```

### Fuzzing Custom Headers
```
wfuzz -z file,wordlist/general/common.txt -H "User-Agent: FUZZ" http://testphp.vulnweb.com/
wfuzz -z file,wordlist/general/common.txt -H "myheader: headervalue" -H "myheader2: headervalue2" http://testphp.vulnweb.com/FUZZ
wfuzz -z file,wordlist/general/common.txt -H "myheader: headervalue" -H "User-Agent: Googlebot-News" http://testphp.vulnweb.com/FUZZ
```

### Using a Proxy
```
wfuzz -z file,wordlist/general/common.txt -p localhost:8080 http://testphp.vulnweb.com/FUZZ
wfuzz -z file,wordlist/general/common.txt -p localhost:2222:SOCKS5 http://testphp.vulnweb.com/FUZZ
wfuzz -z file,wordlist/general/common.txt -p localhost:8080 -p localhost:9090 http://testphp.vulnweb.com/FUZZ
```

### Fuzzing Authentication 
```
wfuzz -z list,nonvalid-httpwatch --basic FUZZ:FUZZ https://www.httpwatch.com/httpgallery/authentication/authenticatedimage/default.aspx
```

### Recursive Fuzzing: 
The -R switch can be used to specify a payload recursion’s depth. To search for existing directories and then fuzz within these directories again using the same payload
```
wfuzz -z list,"admin-CVS-cgi\-bin"  -R1 http://testphp.vulnweb.com/FUZZ
```

### Writing to a File
Wfuzz supports writing the results to a file in a different format.This is performed by plugins called “printers”. The available printers can be listed executing:
```
wfuzz -e printers
```

### Write to outputfile in json format
```
wfuzz -f /tmp/outfile,json -w wordlist/general/common.txt http://testphp.vulnweb.com/FUZZ
```
### Show results in JSON format use the following command
```
wfuzz -o json -w wordlist/general/common.txt http://testphp.vulnweb.com/FUZZ
```

# Finding Subdomains:
### sublist3r
```
sudo apt install sublist3r
```

-d for domain, -t threads
```
sublist3r -d tesla.com -t 100
```

## owasp amass (best tool for searching out sub domains)
lookup ono github

# crt.sh website certificate finger printing
```
https://crt.sh use search bar
% = wildcard
Example: %.tesla.com will search *.tesla.com
```

## googlefu
```
site:tesla.com 
site:tesla.com -www
```
#searches the site without the www part of the url
```
site:tesla.com filetype:docx
site:tesla.com filetype:pdf
```

# dig:
### Perform DNS IP Lookup
```
dig a domain-name-here.com @nameserver 
```
### Perform MX Record Lookup
```
dig mx domain-name-here.com @nameserver
```
### Perform Zone Transfer with DIG
```
dig axfr domain-name-here.com @nameserver
```

### find IP of current machine
```
dig +short myip.opendns.com @resolver1.opendns.com
```
### Query Domain “A” Record 
```
dig <website or ip-address>
```
### Query Domain “A” Record with +short
```
dig <website or ip-address> +short
```
### Querying MX Record for Domain
```
dig <website or ip-address> MX
```
### Querying Start of Authority Record for Domain
```
dig <website or ip-address> SOA
```
### Querying TTL Record for Domain
```
dig <website or ip-address> TTL
```
### Querying ALL DNS Records Types
```
dig <website or ip-address>  ANY +noall +answer
```
### DNS Reverse Look-up
```
dig -x <website or ip-address>
```



# nslookup:

### Query Domain “A” Record 
```
nslookup <website>  
nslookup -type=a <website> 
```
### Querying NS (NameServer) Record for Domain
```
nslookup -type=ns <website>  
```
### Querying MX (MailExchange) Record for Domain
```
nslookup -type=mx <website> 
```
### Querying Start of Authority Record for Domain
```
nslookup -type=soa <website> 
```
### Querying ALL DNS Records Types
```
nslookup -type=any <website>  
```
### DNS Reverse Look-up
```
nslookup <ip-address>  
```
### Querying ALL TXT Records
```
nslookup -type=txt <website> 
nslookup -type=txt google.com
Server:		127.0.0.53
Address:	127.0.0.53#53
```

# DNS Zone Transfers:
### Windows DNS zone transfer
```
nslookup -> set type=any -> ls -d blah.com 
```

### Linux DNS zone transfer
```
dig axfr blah.com @ns1.blah.com
```


# fingerprinting:

## nmap 

## netcat

## wappalyzer (firefox add-on)
will return what was used to build the website. 

## https://builtwith.com
will return what was used to build the website. 

## whatweb (command line tool built into kali)
```
whatweb https://tesla.com
```
will return what was used to build the website. 


# Previous data breaches:
```
HaveIBeenPwned
BreachParse
WeLeakInfo
```

# Email Recon:
## hunter.io
search for public info on emails 
```
https://hunter.io/users/sign_in
```

## breach-parse
search through known breaches for usernames and passwords (for credential stuffing)
https://github.com/hmaverickadams/breach-parse
```
./breach-parse.sh @tesla.com tesla.txt
```
will create: 
1. tesla-master.txt
2. tesla-passwords.txt
3. tesla-users.txt

## theharvester
-d is the target, -l is how many searches deep you want to go, -b search engine to use

will return emails, domains, and ip addresses
```
theharvester -d tesla.com -l 500 -b google
```

# Target Validation:
## WHOIS enumeration
```
whois domain-name-here.com 
```


# dns recon:
### dnsrecon Basic Usage 
```
dnsrecon -d <website>
```
Scan a domain (-d example.com), use a dictionary to brute force hostnames (-D /usr/share/wordlists/dnsmap.txt), 

do a standard scan (-t std), and save the output to a file (–xml dnsrecon.xml):
```
dnsrecon -d example.com -D /usr/share/wordlists/dnsmap.txt -t std --xml dnsrecon.xml
```

dnsrecon -h
```
usage: dnsrecon.py [-h] [-d DOMAIN] [-n NS_SERVER] [-r RANGE] [-D DICTIONARY]
                   [-f] [-t TYPE] [-a] [-s] [-g] [-b] [-k] [-w] [-z]
                   [--threads THREADS] [--lifetime LIFETIME] [--tcp] [--db DB]
                   [-x XML] [-c CSV] [-j JSON] [--iw] [-v]

optional arguments:
  -h, --help            show this help message and exit
  -d DOMAIN, --domain DOMAIN
                        Target domain.
  -n NS_SERVER, --name_server NS_SERVER
                        Domain server to use. If none is given, the SOA of the
                        target will be used.
  -r RANGE, --range RANGE
                        IP range for reverse lookup brute force in formats
                        (first-last) or in (range/bitmask).
  -D DICTIONARY, --dictionary DICTIONARY
                        Dictionary file of subdomain and hostnames to use for
                        brute force. Filter out of brute force domain lookup,
                        records that resolve to the wildcard defined IP
                        address when saving records.
  -f                    Filter out of brute force domain lookup, records that
                        resolve to the wildcard defined IP address when saving
                        records.
  -t TYPE, --type TYPE  Type of enumeration to perform.
  -a                    Perform AXFR with standard enumeration.
  -s                    Perform a reverse lookup of IPv4 ranges in the SPF
                        record with standard enumeration.
  -g                    Perform Google enumeration with standard enumeration.
  -b                    Perform Bing enumeration with standard enumeration.
  -k                    Perform crt.sh enumeration with standard enumeration.
  -w                    Perform deep whois record analysis and reverse lookup
                        of IP ranges found through Whois when doing a standard
                        enumeration.
  -z                    Performs a DNSSEC zone walk with standard enumeration.
  --threads THREADS     Number of threads to use in reverse lookups, forward
                        lookups, brute force and SRV record enumeration.
  --lifetime LIFETIME   Time to wait for a server to response to a query.
  --tcp                 Use TCP protocol to make queries.
  --db DB               SQLite 3 file to save found records.
  -x XML, --xml XML     XML file to save found records.
  -c CSV, --csv CSV     Comma separated value file.
  -j JSON, --json JSON  JSON file.
  --iw                  Continue brute forcing a domain even if a wildcard
                        records are discovered.
  -v                    Enable verbose
```

# Host:
### Query Public DNS records
```
host <website>
```
### Query NS (NameServer) records
```
host -t ns <website>
```
### Query MX (MailExchange) records
```
host -t mx 
```
### # DNS transfer
```
host -t axfr <old-website> <new-website>
```
### In the case of a successful DNS transfer, 
you should be able to get the full DNS zone for the given domain name we are using -l option, which is another way to list all DNS records from a domain name—while testing the vulnerable site zonetransfer.me
```
host -l zonetransfer.me nsztm1.digi.ninja
```


# DNSenum:
avoiding reverse lookup (–noreverse) and saving the output into a file.xml (-o) while querying securitytrails.com
```
dnsenum --noreverse -o file.xml securitytrails.com
```
use the Google search engine to “scrape” the results and get a list of subdomains.
-p specifies the number of pages searched on Google that will be processed (by default 5 pages)
-s option defines the maximum number of subdomains that will be extracted from Google (default is 15)
```
dnsenum --dnsserver ns3.p16.dynect.net github.com -p 10 -s 50
```

# nmap:
attempt to enumerate DNS hostnames by brute forcing popular subdomain names
```
nmap -T4 -p 53 --script dns-brute <website>
```

# Fierce:
```
fierce -dns <website>
```

# whois:
```
whois  <website>
```
#wget Clone a Webstie for off line viewing:
## basic
```
wget -r -nH <website>
```
## Better!!!
```
wget -m -k -K -E -r -nH <website>
```
```
-m,  --mirror			shortcut for -N -r -l inf --no-remove-listing
-k,  --convert-links		make links in downloaded HTML or CSS point to local files
-K,  --backup-converted	before converting file X, back up as X.orig
-E,  --adjust-extension	save HTML/CSS documents with proper extensions
-r,  --recursive		specify recursive download
-nH, --no-host-directories	don't create host directories
```

# SMTP
```
nc -nvv <IP-ADDRESS> 25  
telnet <IP-ADDRESS> 25  
```




