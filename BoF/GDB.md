https://webcache.googleusercontent.com/search?q=cache:XB6wWoYCa8cJ:https://oxasploits.com/posts/simple-buffer-overflow-exploitation-walkthrough-gdb/&hl=en&gl=us&client=ubuntu-sn

# GDB commands
```
gdb ./pwnme           # run a program named pwnme in GDB 
info functions        # look at the functions that are inside the binary by using typing 
disas main            # short for disasemble main which will show the assembly code for the main function of the program.
info breakpoints      # look at breakpoints that have been set
info registers        # look at the curent values of the registers
b main                # set breakpoint at main
b * main+39           # set breakpoint 
b * 0x64413764        # set breakpoint by address
r                     # run
p system              # will give the address of where system is located
p exit                # gives the exit address
x/20s $rsp            # x : eXamine; 20s : 20 values in string; $rsp : for register RSP (Stack Pointer)
```

# msf
1. The following command can be used to generate a 500 character non repeating pattern to overlow the program:
```
/usr/bin/msf-pattern_create -l 500
```
2. after running the program and adding the pattern created by msf
- To view the curent values of the registers within GDB use the command:
```
info registers
```
Take the value held in the EIP register. In this case it is 0x64413764. This value can be passed into msf-pattern_offset to find out the offset necessary to crash the program:
```
msf-pattern_offset -q 0x64413764
```

# python
1. use python code to print A’s by typing after leaving the GDB
```python
python -c "print 'A' * 63"
```

2. use python code to print A’s and pipe that into the program
```
python -c "print 'A' * 78" | ./overflow
```











