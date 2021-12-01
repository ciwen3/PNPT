# IIS Splash Page Found
"These splash pages means there is usually an endpoint that is intended for use and it does not automatically redirect the user there. For example /login. So when you run an automated scanner against it, it won't find that endpoint and just audits the splash screen."

Fuzz scan identifying preauth SQLi, XSS and open redirects. create a file with ip.txt that includes the IP address of all the servers you want to scan. alternatively make a url.txt and use that. 
```
for ip in $(cat ip.txt); do ffuf -u http://$ip/FUZZ -w wordlist.txt -ac; done
```

### Wordlists: 
1. https://gist.github.com/nullenc0de/96fb9e934fc16415fbda2f83f08b28e7

"I use this exact technique, but generally will set the Host header and use the IP in the -u to speed it up just a bit more. ffuf is the fastest around and -ac has an excellent analyzer that produces basically-zero errors"

"I create custom lists after initial targeting with Photon. merge_webpath_list sorts from several sources, namely leaky-paths, ffufplus, commonspeak2, SecLists, Sn1per, RobotsDisallowed, and assetnote lists. Tweak further with GoldenNuggets-1 + IIS-ShortName-Scanner"


### References: 
1. https://twitter.com/nullenc0de/status/1417665541947412481
2. https://github.com/irsdl/IIS-ShortName-Scanner
