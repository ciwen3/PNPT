# log4j

Search for applications on your PC that have log4j installed. 


# Windows 
```
gci 'C:\' -rec -force -include *.jar -ea 0 | foreach {select-string "JndiLookup.class" $_} | select -exp Path
```

# Linux 
```
find / 2>/dev/null -regex ".*.jar" -type f | xargs -I{} grep JndiLookup.class "{}"
```


