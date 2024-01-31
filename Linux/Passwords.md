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

# Hashcat
- https://hashcat.net/wiki/doku.php?id=hashcat
- https://rednode.com/pentest/hashcat-cheat-sheet/

## Installation
```
apt install cmake build-essential -y
apt install checkinstall git -y
git clone https://github.com/hashcat/hashcat.git
make && make install
```

### Performance on nVidia 3080 Ti
Performance check for all supported hash:
```
hashcat -b
```
Here is the full output

Performance check for specific hash:
```
hashcat -b -m 100
```

## Hashcat Basic Command
#### Available commands
```
hashcat --help
```
### Identify hash
```
hashcat --identify hash.txt
```
### Restore Session
```
hashcat --restore
hashcat --restore --session session_name
```

This command will make a dictionary attack against SHA1 hash by specifying session name

### Start Brute Forcing
```
hashcat -a 0 -m 100 --session session1 hash.txt pass.txt
```
### Restore later, if you terminated the brute force
```
hashcat --restore --session session1
```
-a 0 is the attack mode, -m 100 is the hash type, --session session1 is the session name to restore later

### Attack Mode 
1. Dictionary Attack            -a 0 
2. Combination Attack           -a 1 
3. Brute Force Attack           -a 3
4. Mask Attack and Hybrid       -a 6 or 7
5. Rule Based Attack            
6. Association                  -a 9

#### Dictionary Attack
If this attack mode is used, hashcat will use a dictionary file to check against the hash/hashes. The dictionary file could be rockyou.txt or other better one.

Example:
```
hashcat -a 0 -m 100 --session session1 hash.txt words.txt
```

### Combination Attack
This attack mode combine two dictionary to make valid passwords. For example if we have words.txt contains:
- password
- admin
- And words1.txt

City
Then with this attack mode password word will be generated contains:

Command:
```
hashcat -a 1 -m 100 hash.txt words.txt words1.txt
```
Valid password will be generated:

passwordCity
adminCity
It is also possible to append or prepends additional characters:
```
hashcat -a 1 --rule-left='$#' --rule-right='$$' --stdout words.txt words1.txt
```
password#City$
admin#City$

Example
```
hashcat -a 1 -m 100 --rule-left='$#' --rule-right='$$' words.txt words1.txt
```

### Brute Force Attack
Traditionally brute force mean, try all possible words combination of a-zA-z~!@#$%^&*()_+=|\]}{/ which is not realistic(at least for me). If we want to brute force e61a5821062add06b1b6e96a228c378d6f187cec with length of 8, the command is:
```
hashcat -a 3 -m 100 -O -1 ?u?l?s?d /tmp/hash.txt ?1?1?1?1?1?1?1?1
```
It needs more than 3 days:

Imagine, how long hashcat needs to crack a hash of 10 chars password(2 years?).

### Mask and Charsets
Hashcat charsets:
```
?l = abcdefghijklmnopqrstuvwxyz
?u = ABCDEFGHIJKLMNOPQRSTUVWXYZ
?d = 0123456789
?h = 0123456789abcdef
?H = 0123456789ABCDEF
?s = «space»!"#$%&'()*+,-./:;<=>?@[\]^_`{|}~
?a = ?l?u?d?s
?b = 0x00 - 0xff
```
So a custom charsets can be like:
```
-1 ?l?u?d
-1 ubcdefUBCDEF?s?d
```

Example
Using custom charset technique we still can crack the password in a short time:

#d574df7a0e1fe169b3743344c3f69c0b14ae86a1:Test12345#
```
hashcat -a 3 -m 100 -O -1 esTt?d?s /tmp/hash.txt Test?1?1?1?1?1?1
```
#870d1afa2fc48ebbf1cd2c549ee2d456ad470bc1:Test123#
```
hashcat -a 3 -m 100 -O -1 Test?d?s /tmp/hash.txt ?d?d?d?s
```

The requirement for this to work we need to know/guess the Password length, and first few chars. But if we know nothing about the password then best bet is Rule based attack with a good dictionary.

### Association attack
This is a new feature added to hashcat which is use an username, a filename, a hint, or any other pieces of information which could have had an influence in the password generation to attack one specific hash.

Example
```
hashcat -m 3200 has1.txt words.txt -o result.txt -a 9 -r /opt/hashcat/rules/best64.rule
```

### Hybrid Attack
Hybrid attack is combined dictionary with Brute force attack. This mean, the brute force word will be appended or prepended.

As an example the words.txt contains:

password
admin
If we want to add all possible 4 digits at the end of each word in the words.txt, following command will do the trick:
```
.... -a 6 words.txt ?d?d?d?d
```
and if we want to prepend:
```
.... -a 7 ?d?d?d?d words.txt
```
As a demonstration, hashcat is in --stdout mode:
```
test@redtm: hashcat -a 6 --stdout words.txt ?d
password1
password0
password2
password3
password9
password4
password5
password8
password7
password6
admin1
admin0
admin2
admin3
admin9
admin4
admin5
admin8
admin7
admin6

test@redtm: hashcat -a 6 -j '^#' --stdout words.txt ?d
#password1
#password0
#password2
#password3
#password9
#password4
#password5
#password8
#password7
#password6
#admin1
#admin0
#admin2
#admin3
#admin9
#admin4
#admin5
#admin8
#admin7
#admin6
```

Example
If appended then -a 6 and if prepended -a 7

Appened brute force digits and also prepend an special char

Cracked- 03174b1c507223f0b5bb5349cf999c33678bd0fc:#password1

```
hashcat -m 100 -a 6 -j '^#' hash2.txt words.txt ?d
```

Prepend brute forced digits and appened an special char
Cracked - 734eab43f4d197ab226ce5b12cfcc4ded486af72:21admin#

```
hashcat -m 100 -a 7 -k '$#' hash2.txt ?d?d words.txt
```

### Rule-based attack(Favorite)
This is the most efficient attack for password cracking. A simple password can be converted to a complex password with hashcat rules. For example with only one word password combining two hashcat rules can generate 44113 unique complex password.

When Rule-based attack is useful?
Common dictionary failed.
Password is in a minimum length.
Password has a specific policy(Upper+Lower+Num+Special=Valid password?).
If we want to do traditional brute force a hash of plaintext Pas$w0rd! it may take years. Rockyou.txt will fail because it does not has such a complex word but it must contains password . Peoples choose the easy password but meet the password policy just by replacing some characters.

Here rule based attack comes to play.

Built-in rules in hashcat
```
test@redtm: ls /opt/hashcat/rules/
best64.rule      d3ad0ne.rule     generated.rule           InsidePro-HashManager.rule   oscommerce.rule     T0XlC-insert_00-99_1950-2050_toprules_0_F.rule  T0XlC.rule     toggles2.rule  toggles5.rule
combinator.rule  dive.rule        hybrid                   InsidePro-PasswordsPro.rule  rockyou-30000.rule  T0XlC-insert_space_and_special_0_F.rule         T0XlCv1.rule   toggles3.rule  unix-ninja-leetspeak.rule
custom.rule      generated2.rule  Incisive-leetspeak.rule  leetspeak.rule               specific.rule       T0XlC-insert_top_100_passwords_1_G.rule         toggles1.rule  toggles4.rule

test@redtm: ls /opt/hashcat/rules/hybrid
append_d_passthrough.rule    append_hl.rule               append_ldus_passthrough.rule  append_lus.rule             prepend_ds_passthrough.rule   prepend_hu.rule                prepend_l_passthrough.rule    prepend_s.rule
append_d.rule                append_hu_passthrough.rule   append_ldus.rule              append_s_passthrough.rule   prepend_ds.rule               prepend_ld_passthrough.rule    prepend_l.rule                prepend_u_passthrough.rule
append_ds_passthrough.rule   append_hu.rule               append_l_passthrough.rule     append_s.rule               prepend_du_passthrough.rule   prepend_ld.rule                prepend_ls_passthrough.rule   prepend_u.rule
append_ds.rule               append_ld_passthrough.rule   append_l.rule                 append_u_passthrough.rule   prepend_du.rule               prepend_lds_passthrough.rule   prepend_ls.rule               prepend_us_passthrough.rule
append_du_passthrough.rule   append_ld.rule               append_ls_passthrough.rule    append_u.rule               prepend_dus_passthrough.rule  prepend_lds.rule               prepend_lu_passthrough.rule   prepend_us.rule
append_du.rule               append_lds_passthrough.rule  append_ls.rule                append_us_passthrough.rule  prepend_dus.rule              prepend_ldu_passthrough.rule   prepend_lu.rule
append_dus_passthrough.rule  append_lds.rule              append_lu_passthrough.rule    append_us.rule              prepend_hl_passthrough.rule   prepend_ldu.rule               prepend_lus_passthrough.rule
append_dus.rule              append_ldu_passthrough.rule  append_lu.rule                prepend_d_passthrough.rule  prepend_hl.rule               prepend_ldus_passthrough.rule  prepend_lus.rule
append_hl_passthrough.rule   append_ldu.rule              append_lus_passthrough.rule   prepend_d.rule              prepend_hu_passthrough.rule   prepend_ldus.rule              prepend_s_passthrough.rule
```

Combine two or more rules
In my opinion, For effectiveness it is best to combine two or more rules to meet the password policy. For example:
```
hashcat ..... -r /opt/hashcat/rules/leetspeak.rule -r /opt/hashcat/rules/InsidePro-HashManager.rule ...
```
Can we Crack sha1 of P@ssword?
I have not tried all rules but i think a single rule can’t crack it
```
hashcat -a 0 -m 100 -r /opt/hashcat/rules/leetspeak.rule hash.txt words.txt
```
But combining two rule was able to crack
```
hashcat -a 0 -m 100 -r /opt/hashcat/rules/leetspeak.rule -r /opt/hashcat/rules/InsidePro-HashManager.rule hash.txt words.txt
```
Can we Crack sha1 of P@ssw0rd92?
I was able to crack the hash by combining 3 rules:
```
hashcat -a 0 -m 100 -r /opt/hashcat/rules/leetspeak.rule -r /opt/hashcat/rules/InsidePro-HashManager.rule -r /opt/hashcat/rules/best64.rule hash.txt words.txt
```

### Writing rules
Hashcat allow to write our own rule. This is useful when we want more custom word from a dictionary file. For example, combining bellow rule can generate P@ssw0rd1@ if the dictionary has password word:
```
$@
^%
```


# Password Searches:
### Grep hardcoded passwords:
```
#Use grep to look for user in filename
grep -i user [filename]
#Use grep to look for pass in filename
grep -i pass [filename]
#Use grep to look for password in filename
grep -C 5 "password" [filename]
```

### Find to locate Password Files:
```
#find php file and check them for the variable $password
find . -name "*.php" -print0 | xargs -0 grep -i -n "var $password"
# search for .txt files with admin in the name
find / -type f -iname "*admin*.txt"
```

### Known Files to check:
- /home/[USER]/.ssh/
- /etc/shadow
- /etc/passwd
- /home/[USER]/.bash_history
- /var/lib/mysql/mysql/user.MYD


# Generate hashes:
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
