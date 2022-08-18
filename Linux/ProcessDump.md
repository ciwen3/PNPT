# DD restore a delted file running in memory
if the process ID is 2060304 using the command ps to find the process ID
```
cd /proc/2060304/ # file running in Memory as process ID# 2060304
ls
cat maps  # will tell memory location
```
## Example: 
```
                                                                                                                                                                                  
┌──(kali㉿kali)-[/proc]
└─$ cd ./2060304
                                                                                                                                                                                                                                            
┌──(kali㉿kali)-[/proc/2060304]
└─$ ls
arch_status  auxv        cmdline          cpu_resctrl_groups  environ  fdinfo   limits     maps       mounts      ns         oom_score      patch_state  root       sessionid  smaps_rollup  statm    task            timerslack_ns
attr         cgroup      comm             cpuset              exe      gid_map  loginuid   mem        mountstats  numa_maps  oom_score_adj  personality  sched      setgroups  stack         status   timens_offsets  uid_map
autogroup    clear_refs  coredump_filter  cwd                 fd       io       map_files  mountinfo  net         oom_adj    pagemap        projid_map   schedstat  smaps      stat          syscall  timers          wchan
                                                                                                                                                                                                                                            
┌──(kali㉿kali)-[/proc/2060304]
└─$ cat maps     
56549ce73000-56549ce8a000 r--p 00000000 08:01 2116757                    /usr/bin/zsh
56549ce8a000-56549cf1f000 r-xp 00017000 08:01 2116757                    /usr/bin/zsh
56549cf1f000-56549cf41000 r--p 000ac000 08:01 2116757                    /usr/bin/zsh
56549cf42000-56549cf44000 r--p 000ce000 08:01 2116757                    /usr/bin/zsh
56549cf44000-56549cf4a000 rw-p 000d0000 08:01 2116757                    /usr/bin/zsh
56549cf4a000-56549cf5e000 rw-p 00000000 00:00 0 
56549da56000-56549dbee000 rw-p 00000000 00:00 0                          [heap]
7fe064438000-7fe0646b8000 r--s 00000000 08:01 2236559                    /usr/share/zsh/functions/Completion/Unix.zwc
7fe0646cb000-7fe0646ce000 r--p 00000000 08:01 2116768                    /usr/lib/x86_64-linux-gnu/zsh/5.8/zsh/computil.so
7fe0646ce000-7fe0646db000 r-xp 00003000 08:01 2116768                    /usr/lib/x86_64-linux-gnu/zsh/5.8/zsh/computil.so
7fe0646db000-7fe0646dd000 r--p 00010000 08:01 2116768                    /usr/lib/x86_64-linux-gnu/zsh/5.8/zsh/computil.so
7fe0646dd000-7fe0646de000 r--p 00011000 08:01 2116768                    /usr/lib/x86_64-linux-gnu/zsh/5.8/zsh/computil.so
7fe0646de000-7fe0646df000 rw-p 00012000 08:01 2116768                    /usr/lib/x86_64-linux-gnu/zsh/5.8/zsh/computil.so
7fe0646df000-7fe064704000 r--s 00000000 08:01 2236726                    /usr/share/zsh/functions/Completion/Zsh.zwc

```


# dump the file from Memory
```
dd if=mem bs=1 ship=$((0xfirst-location)) count=$((0xlength or math to get length)) of=/tmp/output  # use DD to bit for bit copy out of memory
file /tmp/opputput  # to see what kind of file it is
xxd /tmp/output   # shows output in debugger mode
```
## Example: 
```
┌──(kali㉿kali)-[/proc/2060304]
└─$ dd if=mem bs=1 skip=$((0x56549ce73000)) count=$((0x56549ce8a000-0x56549ce73000)) of=/tmp/output 
dd: mem: cannot skip to specified offset
94208+0 records in
94208+0 records out
94208 bytes (94 kB, 92 KiB) copied, 0.216564 s, 435 kB/s

┌──(kali㉿kali)-[/proc/2060304]
└─$ file /tmp/output  
/tmp/output: ELF 64-bit LSB shared object, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, missing section headers at 878152
                    
```

# dump the Heap from Memory
```
dd if=mem bs=1 ship=$((0xfirst-location)) count=$((0xlength or math to get length)) of=/tmp/heap  # use DD to bit for bit copy out of memory
file /tmp/heap  # to see what kind of file it is
xxd /tmp/heap   # shows output in debugger mode
strings /tmp/heap # pull all ascii characters out and put it on screen to see if there is any identifying information
```
## Example: 
```
┌──(kali㉿kali)-[/proc/2060304]
└─$ dd if=mem bs=1 skip=$((0x56549da56000)) count=$((0x56549dbee000-0x56549da56000)) of=/tmp/heap 
dd: mem: cannot skip to specified offset
1671168+0 records in
1671168+0 records out
1671168 bytes (1.7 MB, 1.6 MiB) copied, 3.61462 s, 462 kB/s
```

# copy the EXE file from Proc
```
cd /proc/2060304/
cp /proc/2060304/exe /tmp/Binary
file /tmp/binary
xxd /tmp/binary
strings /tmp/binary
```

# copy the EXE file from Proc and zip it to protect the system
```
7z a -pinfected 2060304-binary.7z /proc/2060304/exe 

gzip -c -N /proc/2060304/exe > /tmp/2060304-exe.gz
zip -e ./binary.zip binary
```
## Example: 
```
┌──(kali㉿kali)-[/tmp]
└─$ 7z a -pinfected 2060304-binary.7z /proc/2060304/exe 

7-Zip [64] 16.02 : Copyright (c) 1999-2016 Igor Pavlov : 2016-05-21
p7zip Version 16.02 (locale=en_US.UTF-8,Utf16=on,HugeFiles=on,64 bits,2 CPUs Intel(R) Core(TM) i7-6700HQ CPU @ 2.60GHz (506E3),ASM,AES-NI)

Scanning the drive:
1 file, 878216 bytes (858 KiB)

Creating archive: 2060304-binary.7z

Items to compress: 1

    
Files read from disk: 1
Archive size: 146 bytes (1 KiB)
Everything is Ok

┌──(kali㉿kali)-[/tmp]
└─$ 7z e -pinfected 2060304-binary.7z

7-Zip [64] 16.02 : Copyright (c) 1999-2016 Igor Pavlov : 2016-05-21
p7zip Version 16.02 (locale=en_US.UTF-8,Utf16=on,HugeFiles=on,64 bits,2 CPUs Intel(R) Core(TM) i7-6700HQ CPU @ 2.60GHz (506E3),ASM,AES-NI)

Scanning the drive for archives:
1 file, 146 bytes (1 KiB)

Extracting archive: 2060304-binary.7z
--
Path = 2060304-binary.7z
Type = 7z
Physical Size = 146
Headers Size = 130
Method = LZMA2:20 7zAES
Solid = -
Blocks = 1

Everything is Ok

Size:       12
Compressed: 146
```




# References:
1. https://youtu.be/uYWTfWV3dQI
2. https://twitter.com/ippsec/status/1503038655304192004?s=27
