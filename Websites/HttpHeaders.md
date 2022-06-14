1. https://book.hacktricks.xyz/network-services-pentesting/pentesting-web/special-http-headers
2. https://github.com/danielmiessler/SecLists/tree/master/Miscellaneous/web/http-request-headers
3. https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Forwarded-Proto


# Headers to Change Location
### Rewrite IP source:

- X-Originating-IP: 127.0.0.1
- X-Forwarded-For: 127.0.0.1
- X-Forwarded: 127.0.0.1
- Forwarded-For: 127.0.0.1
- X-Forwarded-Host: 127.0.0.1
- X-Remote-IP: 127.0.0.1
- X-Remote-Addr: 127.0.0.1
- X-ProxyUser-Ip: 127.0.0.1
- X-Original-URL: 127.0.0.1
- Client-IP: 127.0.0.1
- X-Client-IP: 127.0.0.1
- X-Host: 127.0.0.1
- True-Client-IP: 127.0.0.1
- Cluster-Client-IP: 127.0.0.1
- X-ProxyUser-Ip: 127.0.0.1
- Via: 1.0 fred, 1.1 127.0.0.1
- Connection: close, X-Forwarded-For (Check hop-by-hop headers)

### Rewrite location:

- X-Original-URL: /admin/console
- X-Rewrite-URL: /admin/console
