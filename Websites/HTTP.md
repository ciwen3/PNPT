# HTTP Requests
### NetCat:
https://linux.die.net/man/1/nc
```
nc 127.0.0.1 80 -vvv
GET / HTTP/1.1
```

### Curl: 
https://linux.die.net/man/1/curl
```
curl --header http://127.0.0.1:80
```

### Python: 
https://requests.readthedocs.io/en/latest/
```python3
r = requests.get('https://api.github.com/user', auth=('user', 'pass'))
r.status_code
200
r.headers['content-type']
'application/json; charset=utf8'
r.encoding
'utf-8'
r.text
'{"type":"User"...'
r.json()
{'private_gists': 419, 'total_private_repos': 77, ...}
```
