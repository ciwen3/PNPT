# Passwords

# Linux Password Info:
```
Example Password: $1$Etg2ExUZ$F9NTP7omafhKIlqaBMqng1
		  $[ALGORITHM]$[SALT]$[HASH of SALT+PASSWORD]

1. first field tell's you the hashing algorithm
-----------------------------------------------
$1 = MD5 		22 characters
$2 = Blowfish 		
$2a= eksblowfish 	
$5 = SHA-256 		43 characters
$6 = SHA-512 		86 characters

2. The second field is the salt value
3. The last field is the hash value of salt+password
```

# Cryptography
### Hash Lengths
```
HASH			SIZE/LENGTH
MD5 Hash 		16 Bytes
SHA-1 Hash 		20 Bytes
SHA-256 Hash 		32 Bytes
SHA-512 Hash 		64 Bytes
```

### Hash Examples
```
HASH				EXAMPLE
MD5 Hash Example		8743b52063cd84097a65d1633f5c74f5
MD5 $PASS:$SALT Example		01dfae6e5d4d90d9892622325959afbe:7050461
MD5 $SALT:$PASS			f0fda58630310a6dd91a7d8f0a4ceda2:4225637426
SHA1 Hash Example		b89eaac7e61417341b710b727768294d0e6a277b
SHA1 $PASS:$SALT		2fc5a684737ce1bf7b3b239df432416e0dd07357:2014
SHA1 $SALT:$PASS		cac35ec206d868b7d7cb0b55f31d9425b075082b:5363620024
SHA-256				127e6fbfe24a750e72930c220a8e138275656b8e5d8f48a98c3c92df2caba935
SHA-256 $PASS:$SALT		c73d08de890479518ed60cf670d17faa26a4a71f995c1dcc978165399401a6c4
SHA-256 $SALT:$PASS		eb368a2dfd38b405f014118c7d9747fcc97f4f0ee75c05963cd9da6ee65ef498:560407001617
SHA-512				82a9dda829eb7f8ffe9fbe49e45d47d2dad9664fbb7adf72492e3c81ebd3e29134d9bc12212bf83c6840f10e8246b9db54a4859b7ccd0123d86e5872c1e5082f
SHA-512 $PASS:$SALT		e5c3ede3e49fb86592fb03f471c35ba13e8d89b8ab65142c9a8fdafb635fa2223c24e5558fd9313e8995019dcbec1fb584146b7bb12685c7765fc8c0d51379fd
SHA-512 $SALT:$PASS		976b451818634a1e2acba682da3fd6efa72adf8a7a08d7939550c244b237c72c7d42367544e826c0c83fe5c02f97c0373b6b1386cc794bf0d21d2df01bb9c08a
NTLM Hash Example		b4b9b02e6f09a9bd760f388b67351e2b
```

# John the Ripper:
### bench test John the Ripper
```
john --test
```
### make the shadowfile readable by John the Ripper
```
unshadow /etc/passwd /etc/shadow > /tmp/crack
```
### use John with a wordlist, use built-in mangling rules, and save to file
```
john --wordlist=/PATH/TO/WORDLIST --rules /tmp/crack
```
### show cracked passwords status
```
john --status
```
### show cracked passwords
```
john --show /tmp/crack 
```
### restore an interrupted session
```
john --restore
```

### password cracking
```
john --wordlist=/usr/share/wordlists/rockyou.txt hashes
```
### forced descrypt cracking with wordlist
```
john --format=descrypt --wordlist /usr/share/wordlists/rockyou.txt hash.txt
```
### forced descrypt brute force cracking
``` 
john --format=descrypt hash --show
```

### crack zip file password
https://www.freecodecamp.org/news/crack-passwords-using-john-the-ripper-pentesting-tutorial/
```
zip2john file.zip > zip.hashes
john zip.hashes
```

## Generate MD5 password hash:
```
python -c "import random,string,crypt;
randomsalt = ''.join(random.sample(string.ascii_letters,8));
print crypt.crypt('MySecretPassword', '\$1\$%s\$' % randomsalt)"
```
```
$1$YjOzcqrf$Zqx4sx5CQRuEIFCdOLAJV0
```

## Generate SHA-256 password hash:
```
python -c "import random,string,crypt;
randomsalt = ''.join(random.sample(string.ascii_letters,8));
print crypt.crypt('MySecretPassword', '\$5\$%s\$' % randomsalt)"
```
```
$5$LgsPuaeR$OCtm.3tpbS/wyOZAIy6dsVNP4x0GyohyGebkIz15e88
```

## Generate SHA-512 password hash:
```
python -c "import random,string,crypt;
randomsalt = ''.join(random.sample(string.ascii_letters,8));
print crypt.crypt('MySecretPassword', '\$6\$%s\$' % randomsalt)"
```
```
$6$HMpFTkgb$WqzuqMqYbjWsXFrOtvZPo.1gIkH6HiXJGr4QPv.k26jE.3mE.sdf3dds[...]
```

## Generate SHA-512 password hash:
```
root@kali:~/# mkpasswd  -m sha-512 -S saltsalt -s 
Password: pwned123
$6$saltsalt$HOC6AvLVkxCTYnJ5Tc78.CYF/KdcBDmheMbOGQTqiMUZhdKof7eXjN9/6I3w8smybsEQEaz5Vh8aoGGs71hf20
```


# BASE64 encode/decode:
BASE64 encode
```
echo 'Hello World!' | base64
```
BASE64 decode
```
'SGVsbG8gV29ybGQhCg==' | base64 -d
```
