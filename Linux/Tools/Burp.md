# Burp Suite (Free Version)
## Install Foxy Proxy
```
opions > add 
name: burp
proxy ip: 127.0.0.1
port: 8080
```

## Configure Burp
```
Proxy > Options
make sure the listener is running on 127.0.0.1 8080
```

## Usage:
in firefox with foxy proxy on browse to the site you want to attack. insert information into a field and submit. 

in Burp, proxy should show the raw page information. select action > send to intruder

### Intruder 
#### Positions:
clear all on the right

select the fields you want to attack (ie. username, password, etc.) and hit add button for each

#### Attack Type:
1. Sniper - attack fields with only one wordlist
2. Battering Ram - 
3. Pitchfork - multiple payloads
4. Cluster Bomb - 

#### Payloads
1. payload set lets you change between payloads you want to use (if using more than one).
2. load a list of things to try. 
3. start attack

### Output: 
start looking at the output and check: 
1. response window at the bottom to see what happened
2. different length replies for different results
3. status codes








