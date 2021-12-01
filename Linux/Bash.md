https://tldp.org/LDP/Bash-Beginners-Guide/html/sect_07_01.html

# Bash features
https://stackoverflow.com/questions/31255699/double-parenthesis-with-and-without-dollar/31255942

$(...) means execute the command in the parens in a subshell and return its stdout. Example:
```
$ echo "The current date is $(date)"
The current date is Mon Jul  6 14:27:59 PDT 2015
```

(...) means run the commands listed in the parens in a subshell. Example:
```
$ a=1; (a=2; echo "inside: a=$a"); echo "outside: a=$a"
inside: a=2
outside: a=1
```

$((...)) means perform arithmetic and return the result of the calculation. Example:
```
$ a=$((2+3)); echo "a=$a"
a=5
```

((...)) means perform arithmetic, possibly changing the values of shell variables, but don't return its result. Example:
```
$ ((a=2+3)); echo "a=$a"
a=5
```

${...} means return the value of the shell variable named in the braces. Example:
```
$ echo ${SHELL}
/bin/bash
```

{...} means execute the commands in the braces as a group. Example:
```
$ false || { echo "We failed"; exit 1; }
We failed
```


# Double-Parentheses Construct
https://tldp.org/LDP/abs/html/dblparens.html

Similar to the let command, the (( ... )) construct permits arithmetic expansion and evaluation. In its simplest form, a=$(( 5 + 3 )) would set a to 5 + 3, or 8. However, this double-parentheses construct is also a mechanism for allowing C-style manipulation of variables in Bash, for example, (( var++ )).

## Example 8-5. C-style manipulation of variables
```
#!/bin/bash
# c-vars.sh
# Manipulating a variable, C-style, using the (( ... )) construct.


echo

(( a = 23 ))  #  Setting a value, C-style,
              #+ with spaces on both sides of the "=".
echo "a (initial value) = $a"   # 23

(( a++ ))     #  Post-increment 'a', C-style.
echo "a (after a++) = $a"       # 24

(( a-- ))     #  Post-decrement 'a', C-style.
echo "a (after a--) = $a"       # 23


(( ++a ))     #  Pre-increment 'a', C-style.
echo "a (after ++a) = $a"       # 24

(( --a ))     #  Pre-decrement 'a', C-style.
echo "a (after --a) = $a"       # 23

echo

########################################################
#  Note that, as in C, pre- and post-decrement operators
#+ have different side-effects.

n=1; let --n && echo "True" || echo "False"  # False
n=1; let n-- && echo "True" || echo "False"  # True

#  Thanks, Jeroen Domburg.
########################################################

echo

(( t = a<45?7:11 ))   # C-style trinary operator.
#       ^  ^ ^
echo "If a < 45, then t = 7, else t = 11."  # a = 23
echo "t = $t "                              # t = 7

echo


# -----------------
# Easter Egg alert!
# -----------------
#  Chet Ramey seems to have snuck a bunch of undocumented C-style
#+ constructs into Bash (actually adapted from ksh, pretty much).
#  In the Bash docs, Ramey calls (( ... )) shell arithmetic,
#+ but it goes far beyond that.
#  Sorry, Chet, the secret is out.

# See also "for" and "while" loops using the (( ... )) construct.

# These work only with version 2.04 or later of Bash.

exit
```


# read
https://www.computerhope.com/unix/bash/read.htm

# Comparison Operators
https://tldp.org/LDP/abs/html/comparison-ops.html

A binary comparison operator compares two variables or quantities. Note that integer and string comparison use a different set of operators.

## integer comparison

-eq
is equal to
```
if [ "$a" -eq "$b" ]
```
-ne
is not equal to
```
if [ "$a" -ne "$b" ]
```
-gt
is greater than
```
if [ "$a" -gt "$b" ]
```
-ge
is greater than or equal to
```
if [ "$a" -ge "$b" ]
```
-lt
is less than
```
if [ "$a" -lt "$b" ]
```
-le
is less than or equal to
```
if [ "$a" -le "$b" ]
```
<
is less than (within double parentheses)
```
(("$a" < "$b"))
```
<=
is less than or equal to (within double parentheses)
```
(("$a" <= "$b"))
```
>
is greater than (within double parentheses)
```
(("$a" > "$b"))
```
>=
is greater than or equal to (within double parentheses)
```
(("$a" >= "$b"))
```
## string comparison

=

is equal to
```
if [ "$a" = "$b" ]
```
##### Caution: Note the whitespace framing the =
```
if [ "$a"="$b" ] is not equivalent to the above.
```
==
is equal to
```
if [ "$a" == "$b" ]
```
This is a synonym for =

Note:	
The == comparison operator behaves differently within a double-brackets test than within single brackets.
```
[[ $a == z* ]]   # True if $a starts with an "z" (pattern matching).
[[ $a == "z*" ]] # True if $a is equal to z* (literal matching).

[ $a == z* ]     # File globbing and word splitting take place.
[ "$a" == "z*" ] # True if $a is equal to z* (literal matching).
```

!=
is not equal to
```
if [ "$a" != "$b" ]
```
This operator uses pattern matching within a [[ ... ]] construct.

<
is less than, in ASCII alphabetical order
```
if [[ "$a" < "$b" ]]

if [ "$a" \< "$b" ]
```
Note that the "<" needs to be escaped within a [ ] construct.

>
is greater than, in ASCII alphabetical order
```
if [[ "$a" > "$b" ]]

if [ "$a" \> "$b" ]
```
Note that the ">" needs to be escaped within a [ ] construct.

-z
string is null, that is, has zero length
```
String=''   # Zero-length ("null") string variable.

if [ -z "$String" ]
then
  echo "\$String is null."
else
  echo "\$String is NOT null."
fi     # $String is null.
```
-n
string is not null.

Caution: The -n test requires that the string be quoted within the test brackets. Using an unquoted string with ! -z, or even just the unquoted string alone within test brackets (see Example 7-6) normally works, however, this is an unsafe practice. Always quote a tested string. [1]

#### Example 7-5. Arithmetic and string comparisons
```
#!/bin/bash

a=4
b=5

#  Here "a" and "b" can be treated either as integers or strings.
#  There is some blurring between the arithmetic and string comparisons,
#+ since Bash variables are not strongly typed.

#  Bash permits integer operations and comparisons on variables
#+ whose value consists of all-integer characters.
#  Caution advised, however.

echo

if [ "$a" -ne "$b" ]
then
  echo "$a is not equal to $b"
  echo "(arithmetic comparison)"
fi

echo

if [ "$a" != "$b" ]
then
  echo "$a is not equal to $b."
  echo "(string comparison)"
  #     "4"  != "5"
  # ASCII 52 != ASCII 53
fi

# In this particular instance, both "-ne" and "!=" work.

echo

exit 0
```
#### Example 7-6. Testing whether a string is null
```
#!/bin/bash
#  str-test.sh: Testing null strings and unquoted strings,
#+ but not strings and sealing wax, not to mention cabbages and kings . . .

# Using   if [ ... ]

# If a string has not been initialized, it has no defined value.
# This state is called "null" (not the same as zero!).

if [ -n $string1 ]    # string1 has not been declared or initialized.
then
  echo "String \"string1\" is not null."
else  
  echo "String \"string1\" is null."
fi                    # Wrong result.
# Shows $string1 as not null, although it was not initialized.

echo

# Let's try it again.

if [ -n "$string1" ]  # This time, $string1 is quoted.
then
  echo "String \"string1\" is not null."
else  
  echo "String \"string1\" is null."
fi                    # Quote strings within test brackets!

echo

if [ $string1 ]       # This time, $string1 stands naked.
then
  echo "String \"string1\" is not null."
else  
  echo "String \"string1\" is null."
fi                    # This works fine.
# The [ ... ] test operator alone detects whether the string is null.
# However it is good practice to quote it (if [ "$string1" ]).
#
# As Stephane Chazelas points out,
#    if [ $string1 ]    has one argument, "]"
#    if [ "$string1" ]  has two arguments, the empty "$string1" and "]" 


echo


string1=initialized

if [ $string1 ]       # Again, $string1 stands unquoted.
then
  echo "String \"string1\" is not null."
else  
  echo "String \"string1\" is null."
fi                    # Again, gives correct result.
# Still, it is better to quote it ("$string1"), because . . .


string1="a = b"

if [ $string1 ]       # Again, $string1 stands unquoted.
then
  echo "String \"string1\" is not null."
else  
  echo "String \"string1\" is null."
fi                    # Not quoting "$string1" now gives wrong result!

exit 0   # Thank you, also, Florian Wisser, for the "heads-up".
```
#### Example 7-7. zmore
```
#!/bin/bash
# zmore

# View gzipped files with 'more' filter.

E_NOARGS=85
E_NOTFOUND=86
E_NOTGZIP=87

if [ $# -eq 0 ] # same effect as:  if [ -z "$1" ]
# $1 can exist, but be empty:  zmore "" arg2 arg3
then
  echo "Usage: `basename $0` filename" >&2
  # Error message to stderr.
  exit $E_NOARGS
  # Returns 85 as exit status of script (error code).
fi  

filename=$1

if [ ! -f "$filename" ]   # Quoting $filename allows for possible spaces.
then
  echo "File $filename not found!" >&2   # Error message to stderr.
  exit $E_NOTFOUND
fi  

if [ ${filename##*.} != "gz" ]
# Using bracket in variable substitution.
then
  echo "File $1 is not a gzipped file!"
  exit $E_NOTGZIP
fi  

zcat $1 | more

# Uses the 'more' filter.
# May substitute 'less' if desired.

exit $?   # Script returns exit status of pipe.
#  Actually "exit $?" is unnecessary, as the script will, in any case,
#+ return the exit status of the last command executed.
```

## compound comparison

-a
logical and

exp1 -a exp2 returns true if both exp1 and exp2 are true.

-o
logical or

exp1 -o exp2 returns true if either exp1 or exp2 is true.

These are similar to the Bash comparison operators && and ||, used within double brackets.
```
[[ condition1 && condition2 ]]
```
The -o and -a operators work with the test command or occur within single test brackets.
```
if [ "$expr1" -a "$expr2" ]
then
  echo "Both expr1 and expr2 are true."
else
  echo "Either expr1 or expr2 is false."
fi
```
