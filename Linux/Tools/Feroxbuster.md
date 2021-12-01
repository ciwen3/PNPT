# Feroxbuster 
https://github.com/epi052/feroxbuster
## Usage:
```
USAGE:
    feroxbuster [FLAGS] [OPTIONS] --url <URL>...

FLAGS:
    -f, --addslash         Append / to each request
    -D, --dontfilter       Don't auto-filter wildcard responses
    -e, --extract-links    Extract links from response body (html, javascript, etc...); make new requests based on
                           findings (default: false)
    -h, --help             Prints help information
    -k, --insecure         Disables TLS certificate validation
    -n, --norecursion      Do not scan recursively
    -q, --quiet            Only print URLs; Don't print status codes, response size, running config, etc...
    -r, --redirects        Follow redirects
        --stdin            Read url(s) from STDIN
    -V, --version          Prints version information
    -v, --verbosity        Increase verbosity level (use -vv or more for greater effect)

OPTIONS:
    -d, --depth <RECURSION_DEPTH>           Maximum recursion depth, a depth of 0 is infinite recursion (default: 4)
    -x, --extensions <FILE_EXTENSION>...    File extension(s) to search for (ex: -x php -x pdf js)
    -H, --headers <HEADER>...               Specify HTTP headers (ex: -H Header:val 'stuff: things')
    -o, --output <FILE>                     Output file to write results to (default: stdout)
    -p, --proxy <PROXY>                     Proxy to use for requests (ex: http(s)://host:port, socks5://host:port)
    -Q, --query <QUERY>...                  Specify URL query parameters (ex: -Q token=stuff -Q secret=key)
    -S, --sizefilter <SIZE>...              Filter out messages of a particular size (ex: -S 5120 -S 4927,1970)
    -s, --statuscodes <STATUS_CODE>...      Status Codes of interest (default: 200 204 301 302 307 308 401 403 405)
    -t, --threads <THREADS>                 Number of concurrent threads (default: 50)
    -T, --timeout <SECONDS>                 Number of seconds before a request times out (default: 7)
    -u, --url <URL>...                      The target URL(s) (required, unless --stdin used)
    -a, --useragent <USER_AGENT>            Sets the User-Agent (default: feroxbuster/VERSION)
    -w, --wordlist <FILE>                   Path to the wordlist
```

## Multiple Values
The command above adds .pdf, .js, .html, .php, .txt, .json, and .docx to each url
```
./feroxbuster -u http://127.1 -x pdf -x js,html -x php txt json,docx
```

## Extract Links from Response Body
Search through the body of valid responses (html, javascript, etc...) for additional endpoints to scan.
```
./feroxbuster -u http://127.1 --extract-links

```

## Grab it all 
```
feroxbuster -e -f -k -x js php ini inf jsp htm html json pdf txt xlsx docx svg axd -w dirsearch.txt -u http://10.129.35.132/login.php 

```




























