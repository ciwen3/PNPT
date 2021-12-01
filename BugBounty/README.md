# Bug Bounty Recon

Open Bounties:
```
verizon media
tesla motors
```

MAKE A SCRIPT TO GO THROUGH EACH OF THESE TOOLS ONE AT A TIME CATTING TO A FILE, IT SHOULD THEN SORT AND UNIQ THE FILE. WILL TAKE SOME MESSING WITH EACH TOOL FOR A WHILE TO FIGURE OUT. 

Check javascript files for api keys and hardcoded username or passwords


## Scope Domain: 
(look up how to do settings in burp suite)
```
Look at bug bounty and see what is allowed. could be domain based like *.tesla.com or could be IP range based. 
```

## Aquisitions:
```
crunchbase.com (business info portal, gives org info)
wikipedia and google are also good places to look up aquisitions. 
Always double check that the quisition still stands nad that th compnay hasnt been sold off and verify the aquisitions are in scope before testing/attacking them. 
```

## ASN Enumeration: 
Autonomous System numbers are given to large enough networks. 
```
http://bgp.he.net
asnlookup.com
maxmind.com
will give you IP addresses for the company
this might not get everything like rouge assests deployed on aws or azure. 

automation: becauseful that it doesn't include extra companies with similar names or part of the name in theirs. 
metabigor by j3ssiejjj
asnlookup by yassine aboukir 

AMASS by jeff foley: # amass intel -asn <asn#>
```

## Reverse WhoIs Lookup:
```
whoxy.com get free apikey
domlink.py https://github.com/vysecurity/DomLink
```

## Ad/Analytics Relationship: 
```
builtwith.com (has chrome and firefox extension)
look at the relationship profile to see all the ad and analytics code used by the site. might be able to find more domains to add to the search. will have to look things up. 
```


## Extra:
```
google-fu: inurl:twitch will look for any domains with twitch in the url. 
google for: copy right text, terms of service test, privacy policy text (like to be reused accross all sub domains).
shodan.io look for common headers and search for those. 
```

## Subdomain Enumeration:
```
Linked and js discovery- burp suite spider, 

Burp suite pro: 
===============
1. turn off passive scanning
2. set forms to auto submit (if feeling frisky, might not be good)
3. set scope to advanced control and use "keyword" of target name (not a normal FQDN)
4. walk or browse main site, then spider all hosts recursively
5. profit 
6. export: will only work from burp suite pro
select all hosts in the site tree
right click the selected hosts
go to "Engagement Tools" -> "Analyze Target"
save as HTML file
copy hosts from target section to your documentation tool

Burp Alternative: 
=================
gospider by j3ssiejjj
hakrawler by hakluke
subdomainizer by neeraj edwards- tries to find potentially sensitive items in js files
subscraper by cillian-collins 

subdoamin scraping- These sites are meant to look up IT related things but can show you other subdoamins: passive total, censys, robtex, waybackmachine, ptrarchive, dnsdb, dnsdumpster, crt.sh, cert spotter, certdb, hacker target, threatminer, threat crowd, virus total? 
google: site:twitch.tv -www.twitch.tv -watch.twitch.tv -dev.twitch.tv this will look for all subdomains minus the ones we already know about

AMASS- 
SUBFINDER- projectdiscovery.io
GITHUB-SUBDOMAINS.PY by gwendal le coguic needs my github API to work
shosubgo by inc0gbyt3 written in go and uses shodan to look for subdomains

tls.bufferover.run
bufferover.com?? sam erb defcontalk about subdomain scraping cloud ranges
daehee park using masscan to do subdomain scraping of cloud ranges



subdomain bruteforcing- 
massdns
AMASS # amass enum -brute -d twitch.tv -src
AMASS # amass enum -brute -d twitch.tv -rf resolvers.txt -w bruteforce.list
shuffledns by projectdiscovert.io wrapper around amass


all.txt dns bruteforce list jhaddix
cewl to parse keywords from a website to make a customer brute force list
assetnote brute force lists!!!!!
altdns by naffy and shubs can do alteration scanning but so can amass


try things like 
ww2.$target.com instead of www.$target.com
origin-sub.domain.com
origin.sub.domain.com
```

## Port Analysis: 
```
MASSCAN: # masscan -p1-65535 -iL $ipfile --max-rate 1800 -oG $outputfile.log
https://danielmiessler.com/study/masscan/
use the output from masscan to feed into nmap for more thourgh port scanning. 
dnmasscan can be used to scan sites as well as ip addresses. masscan can only do ip addresses. 
brutespray by @x90skysn3k uses nmap -oG file as input to check for default credentials 

github and google dorking to find extra stuff like api keys and passwords etc. 
https://gist.github.com/jhaddix/1fb7ab2409ab579178d2a79959909b33  <- script to automate the process for github
gwendal le coguic script called github-search 
"Githib and Sensitive data exposure" talk by @th3gentleman
```


## Screenshotting pages: 
these tools will give you a directory of screenshots that you can scroll through. 
```
aquatone
httpscreenshit
eyewitness

uses tomnomnoms http-probe to verify if http or https is up on the domain before feeding it into the screen capture programs. 
```



## Subdomian take over:
```
EdOverflow can-i-take-over-xyz
checks for cnames no longer pointing to anything. can search for this by finding error pages that would comeback from a cnam eredirect that doesnt work anymore. 
looks for services or subdomains that have been removed but are still pointed to by other services or sites. this can lead to a take over of the subdomain

subover projectdiscover.io in the nuclei scanner, look ofr their subdomina takerover templates in their github page. 
```

## automation/helper: 
```
interlace by michael skelton aka codingo look for guide by kaluke
will help add comminication between tools that would not normally beable to take or read/write the same formats. 

tomnomnom tools (has tons)
```

## Frameworks: 
```
c-tier:
github.com/admiralgaust/bountyrecon
github.com/offhourscoding/recon
github.com/Sambal0x/Recon-tools
github.com/JoshuaMart/AutoPecon
github.com/yourbuddy25/Hunter
github.com/venom26/recon/blob/master/ultimate_recon.sh
github.com/dwisiswant0/5f647e3d406b5e984e6d69d3538968cd

b-tier: 
github.com/capt-meelo/LazyRecon
github.com/phspade/Automated-Scanner
github.com/shmilylty/OneForAll
github.com/SolomonSklash/chomp-scan
github.com/TypeError/domained
github.com/Screetsec/Sudomy
github.com/devanshbatham/Gorecon
github.com/LordNeoStark/tugarecon

a-tier: 
github.com/Edu4rdSHL/finddomain
github.com//SilverPoison/Rock-ON
github.com/epi052/recon-pipeline

s-tier: cost money
Intrigue.io   has open source core
assetnote
spiderfoot
project discovery framework
```

Other:
======
buckets: 



## vulns: 
```
once you have a finger print for a vulnerability search for it everywhere else. 
look at other peoples write up to identify vulnerabilites and the search for the finger print online to replicate the original find. 
```


## check: 
1. how does it handle special characters
2. does it have a login
3. are there multiple user roles for the site (like admin and reg user). 
4. what tech runs the site
5. interesting endpoints
6. what is this application meant for and what does it actually do
7. what user roles exist
8. what do users have access to, ie user vs admin
9. how do the users interact with each other
10. what is meant ot be public vs private and see if you can find the private info of another user without admin privledges
11. look at JS to find hidden endpoints
12. js parser to locate JS and then fuzz the JS
