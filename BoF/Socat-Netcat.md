# Socat-Version:
```
gdb socat -exec="set follow-fork-mode child"
r tcp-listen:4444,reuseaddr exec:./binary,PTY,raw,echo=0
```
```
gdb exec /usr/bin/socat tcp4-l:10001,fork,reuseaddr exec:/home/kali/CanYouHack/overflow
gdb "exec /usr/bin/socat tcp4-l:10001,fork,reuseaddr exec:/home/kali/CanYouHack/overflow"
gdb socat -exec="set follow-fork-mode child"
```



# Ncat-Version
```
gdb ncat -exec="set follow-fork-mode child"
r -l 0.0.0.0 1234 -e ./binary
```
