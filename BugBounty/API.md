
## Common Places to test APIs
1. Request Header
2. Request Parameters
3. URL Parameters
4. File Uploads (PUT/DELETE Requests)
5. Different Request Methods
  - GET: The GET method requests a representation of the specified resource. Requests using GET should only retrieve data.
  - HEAD: The HEAD method asks for a response identical to that of a GET request, but without the response body.
  - POST: The POST method is used to submit an entity to the specified resource, often causing a change in state or side effects on the server.
  - PUT: The PUT method replaces all current representations of the target resource with the request payload.
  - DELETE: The DELETE method deletes the specified resource.
  - CONNECT: The CONNECT method establishes a tunnel to the server identified by the target resource.
  - OPTIONS: The OPTIONS method is used to describe the communication options for the target resource.
  - TRACE: The TRACE method performs a message loop-back test along the path to the target resource.
  - PATCH: The PATCH method is used to apply partial modifications to a resource. 
  - QWE: made up, but fake options can sometimes return a lot of information


## Send malformed JSON Requests
for example add an extra quote:
- {"bugcrowd":"LevelUp0x3""}


## Input Validation Bugs
1. Improper parameterization of requests within application logic (ie. concatonating and treating all input as trusted)
2. Lack of Input Sanitization / Escaping Unsafe Characters
3. Improper Handling of Parameters
4. Insufficient Controls for data types passed (file upload bugs, unicode bugs)




## Things you can Fuzz for
### Input Validation Fuzzing:
1. Remote Code Execution
  - SSTI
  - File Upload? ({"filename":"test.png", "fileContent":"data:image/png;base64,...") can lead to XXE or Stored XSS.
2. Cross Site Scripting
4. Local/Remote File Inclusion
5. SQL/noSQL Injection
6. Request Splitting - Making additional requests to 3rd party APIs through the target APi or vise versa (if allowed).
7. Deserialization
8. XXE and other templated languages
9. Encoding errors with junk characters, Control Character, Emoji, etc
10. File Upload Vulnerability
11. SSRF - APIs that can resolve URLs can be tricked into making requests in the context of the server itself. Can lead to enumeration of private internal network, or gaining access to server metadata in a cloud environment. 
12. Unhandled Input - from 3rd party, can result in unexpected errors in the target application
13. 3rd party API - often have a trusted relationship with the server in someway that can be exploited. 


### Tools you can use
1. Burp or zap proxy
2. Enumeration Tools (Gobuster, Dirb, Feroxbuster)
3. Custom Script
### Pro Tip: speed up fuzzing by making HEAD requests directly to the API endpoints. 

## Rate Limiting
test by making a lot of requests very fast an see if you get an error message

## Make request in various states of authentication
1. unauthenticated user
2. authenticated user
3. developer
4. bot
5. deactivated account
6. bogus credentials
7. add & (or other "illegal" characters) at the end of requests and see what happens 












