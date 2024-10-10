# Automated Tools
1. truffleHog
Searches through git repositories for secrets, digging deep into commit history and branches. This is effective at finding secrets accidentally committed. https://github.com/trufflesecurity/truffleHog
2. Nightfall
https://try.nightfall.ai/radar


# Favorites
| Operator	| Description	| Example |
|-----------|-------------|---------|
| intitle |	which finds strings in the title of a page | intitle:”Your Text” |
|	allintext | which finds all terms in the title of a page | allintext:”Contact” |
|	inurl | which finds strings in the URL of a page | inurl:”news.php?id=” |
|	site | which restricts a search to a particular site or domain | site:yeahhub.com “Keyword” |
|	filetype | which finds specific types of files (doc, pdf, mp3 etc) based on file extension | filetype:pdf “Cryptography” |
|	link | which searches for all links to a site or URL | link:”example.com” |
|	cache | which displays Google’s cached copy of a page | cache:yeahhub.com |
|	info | which displays summary information about a page | info:www.example.com |


```
"BEGIN * PRIVATE KEY" ext:pem | ext:key | ext:txt | ext:csr
intitle:"index of" ".cert.pem" | ".key.pem" | ".crt" | ".pem"
```
