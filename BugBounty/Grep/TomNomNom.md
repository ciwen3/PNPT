# Subdomain fiding: 
https://github.com/tomnomnom

##Tools: 
1. assetfinder - finds subdomains https://github.com/tomnomnom/assetfinder
2. httprobe - checks to see if it is using http or https https://github.com/tomnomnom/httprobe
3. meg - grabs as many pages as it can https://github.com/tomnomnom/meg (consider turbo intruder as an alternative)
4. gf - grep for things based on setup rules, like s3 buckets, AWS keys, etc. https://github.com/tomnomnom/gf
5. html-tool - Take URLs or filenames for HTML documents on stdin and extract tag contents, attribute values, or comments. https://github.com/tomnomnom/hacks/tree/master/html-tool
6. unfurl - remove duplicate urls, can create a wordlist for paths https://github.com/tomnomnom/unfurl


## Process
```
assetfinder --subs-only uber.com > domains.txt
cat domains.txt | httprobe | tee hosts.txt
meg -d 1000 -v / 
grep -Hnri <phrase> *
gf <search-rule> 
unfurl -u paths
```

**Explination:**
1. finds domains
2. checks if they use http or https
3. tries all possible pages for the domain
4. check for what we want
5. grep for predefined search rules using gf
6. extract useful or intersting things from the content. 


## Intersting: 
gron - Make JSON greppable! https://github.com/tomnomnom/gron


## one-liner: grep git repo for pattern:
```
{ find .git/objects/pack/ -name "*.idx"|while read i;do git show-index < "$i"|awk '{print $2}';done;find .git/objects/ -type f|grep -v '/pack/'|awk -F'/' '{print $(NF-1)$NF}'; }|while read o;do git cat-file -p $o;done|grep -E 'pattern'
```

```
{ find .git/objects/pack/ -name "*.idx"|while read i;do git show-index < "$i"|awk '{print $2}';done;find .git/objects/ -type f|grep -v '/pack/'|awk -F'/' '{print $(NF-1)$NF}'; }|while read o;do git cat-file -p $o;done|grep -ai 'pattern'
```

this will search through everything for the 'pattern' you want to find. 

to use: 
download repo and run the command
```
{ find .git/objects/pack/ -name "*.idx"|while read i;do git show-index < "$i"|awk '{print $2}';done;find .git/objects/ -type f|grep -v '/pack/'|awk -F'/' '{print $(NF-1)$NF}'; }|while read o;do git cat-file -p $o;done|grep -ai 'password'
```

to use look for bug bounty programs that have git repo in scope. download the repo and run the command. 
**Keywords to search for:**
- funct
- pass
- password 
- uid
- url
- urls
- uber (to find all uber related urls, that can then be used to check for exploits)

  **TIP: instead of piping into grep pipe it into gf and use predefined rules to find interesting things.**
  

