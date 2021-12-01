## Substitue lowercase "t" for uppercase "T":
```
sed 's/t/T' filename > newfile.txt
     ^               ^-- write to newfile.txt
      -- Substitue lowercase "t" for uppercase "T"
```
## Substitue lowercase "t" for uppercase "T" when it is at the beggining of the line globally:
```
sed 's/^t/T/g' filename
       ^    ^-- global (all instances in the file)
       -- only if it is at the begginging of the line
```

## Substitue lowercase "t" for uppercase "T" when it is at the beggining of the line globally:
```
sed -i 's/t$/T/g' filename
     ^     ^-- only if it is at the end of the line
      -- make changes to the file
```
## Change all numbers to asteriks:
```
sed 's/[0-9]/*/g' filename
```
- [a-z] lowercase letters
- [A-Z] Uppercase letters      
- [a-z][A-Z] looking for lowercase followed by Uppercase
- [a-zA-Z] all letters
- [A-z} all letters
- [A-z0-9] All letters and numbers
- [0-z] all letters and numbers

## keep the same but put parenthesis around it:
```
sed 's/[0-9]/(&)/g' filename
              ^-- keep the same but put parenthesis around it.
```
## keep the same but duplicate it and put parenthesis around it:
```
sed 's/[0-9]/(&&)/g' filename
               ^-- keep the same but duplicate it and put parenthesis around it.
```
## will look for all combinations (1 or 2 digit numbers):
```
sed 's/[0-9][0-9]*/(&)/g' filename
                 ^-- will look for all combinations (1 or 2 digit numbers)
```

## remove the FIRST word of the line (by substituting it with nothing) and empty space after it:
```
sed 's/\w*.//' filename
       ^  ^-- remove the space after the 1st word
        -- remove the first word of the line (by substituting it with nothing)
```
## remove the LAST word of the line (by substituting it with nothing) and empty space after it:
```
sed 's/\w*.$//' filename
           ^-- makes it the last word of the line instead of the first 
```


## Remove Leading whitespace:
```
sed 's/^ *//g' <file-name>
```
