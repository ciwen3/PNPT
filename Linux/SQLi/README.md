# SQLi:
1. https://sqlwiki.netspi.com/
2. https://github.com/NetSPI/PowerUpSQL/wiki

# SQL Injection Type:
## In-band SQLi (Classic SQLi): 
In-band SQL Injection is the most common and easy-to-exploit of SQL Injection attacks. In-band SQL Injection occurs when an attacker is able to use the same communication channel to both launch the attack and gather results. The two most common types of in-band SQL Injection are Error-based SQLi and Union-based SQLi.

## Error-based SQLi: 
Error-based SQLi is an in-band SQL Injection technique that relies on error messages thrown by the database server to obtain information about the structure of the database. In some cases, error-based SQL injection alone is enough for an attacker to enumerate an entire database.

## Union-based SQLi: 
Union-based SQLi is an in-band SQL injection technique that leverages the UNION SQL operator to combine the results of two or more SELECT statements into a single result which is then returned as part of the HTTP response.

## Inferential SQLi (Blind SQLi): 
Inferential SQL Injection, unlike in-band SQLi, may take longer for an attacker to exploit, however, it is just as dangerous as any other form of SQL Injection. In an inferential SQLi attack, no data is actually transferred via the web application and the attacker would not be able to see the result of an attack in-band (which is why such attacks are commonly referred to as “blind SQL Injection attacks”). Instead, an attacker is able to reconstruct the database structure by sending payloads, observing the web application’s response and the resulting behavior of the database server. The two types of inferential SQL Injection are Blind-boolean-based SQLi and Blind-time-based SQLi.

## Boolean-based (content-based) Blind SQLi: 
Boolean-based SQL Injection is an inferential SQL Injection technique that relies on sending an SQL query to the database which forces the application to return a different result depending on whether the query returns a TRUE or FALSE result. Depending on the result, the content within the HTTP response will change, or remain the same. This allows an attacker to infer if the payload used returned true or false, even though no data from the database is returned.

## Time-based Blind SQLi: 
Time-based SQL Injection is an inferential SQL Injection technique that relies on sending an SQL query to the database which forces the database to wait for a specified amount of time (in seconds) before responding. The response time will indicate to the attacker whether the result of the query is TRUE or FALSE. epending on the result, an HTTP response will be returned with a delay, or returned immediately. This allows an attacker to infer if the payload used returned true or false, even though no data from the database is returned.

## Out-of-band SQLi: 
Out-of-band SQL Injection is not very common, mostly because it depends on features being enabled on the database server being used by the web application. Out-of-band SQL Injection occurs when an attacker is unable to use the same channel to launch the attack and gather results. Out-of-band techniques, offer an attacker an alternative to inferential time-based techniques, especially if the server responses are not very stable (making an inferential time-based attack unreliable).

## Voice Based Sql Injection: 
It is a sql injection attack method that can be applied in applications that provide access to databases with voice command. An attacker could pull information from the database by sending sql queries with sound.


# SQL Injection Vulnerability Scanner Tool’s:
```
SQLMap — Automatic SQL Injection And Database Takeover Tool
jSQL Injection — Java Tool For Automatic SQL Database Injection
BBQSQL — A Blind SQL-Injection Exploitation Tool
NoSQLMap — Automated NoSQL Database Pwnage
Whitewidow — SQL Vulnerability Scanner
DSSS — Damn Small SQLi Scanner
explo — Human And Machine Readable Web Vulnerability Testing Format
Blind-Sql-Bitshifting — Blind SQL-Injection via Bitshifting
Leviathan — Wide Range Mass Audit Toolkit
Blisqy — Exploit Time-based blind-SQL-injection in HTTP-Headers (MySQL/MariaDB)
```


# Test: 
## Any Field
```
'
"
```


## Login
Username: 
```
" or ""="
```
Password:
```
" or ""="
```
Result:
```
SELECT * FROM Users WHERE Name ="" or ""="" AND Pass ="" or ""=""
```
The SQL above is valid and will return all rows from the "Users" table, since OR ""="" is always TRUE.



## Other tests
```
' or 1=1--
' and 1=1--
' or 1=1;--
' and 1=1;--
'OR 1 OR'
105 OR 1=1
```
