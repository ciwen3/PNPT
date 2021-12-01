# CORS Scanner 
https://github.com/chenjj/CORScanner

Fast CORS misconfiguration vulnerabilities scanner

### Setup:
```
git clone https://github.com/chenjj/CORScanner.git
```
### Install dependencies
```
sudo pip install -r requirements.txt
```
## Usage:
### To check CORS misconfigurations of specific domain:
```
python cors_scan.py -u example.com
```
### To check CORS misconfigurations of specific URL:
```
python cors_scan.py -u http://example.com/restapi
```
### To check CORS misconfiguration with specific headers:
```
python cors_scan.py -u example.com -d “Cookie: test”
```
### To check CORS misconfigurations of multiple domains/URLs:
```
python cors_scan.py -i top_100_domains.txt -t 100
```
