1. https://ftp.gnu.org/old-gnu/Manuals/gdb/html_node/gdb_1.html
2. https://webcache.googleusercontent.com/search?q=cache:XB6wWoYCa8cJ:https://oxasploits.com/posts/simple-buffer-overflow-exploitation-walkthrough-gdb/&hl=en&gl=us&client=ubuntu-sn
3. https://bufferoverflows.net/for-beginners-linux-buffer-overflow-challenge/


# GDB commands
```
gdb ./pwnme           # run a program named pwnme in GDB 
info functions        # look at the functions that are inside the binary by using typing 
disas main            # short for disasemble main which will show the assembly code for the main function of the program.
info breakpoints      # look at breakpoints that have been set
info registers        # look at the curent values of the registers
break main                # set breakpoint at main
next                  # will let you go through one operation at a time after the break point has been hit
b * main+39           # set breakpoint 
b * 0x64413764        # set breakpoint by address
disable               # disbales all breakpoints
clear                 # Delete any breakpoints at the next instruction to be executed in the selected stack frame
run                   # run
list                  # list source code that GDB is going through
print num             # will print the current variable value for variable num
p system              # will give the address of where system is located
p exit                # gives the exit address
info locals           # lists all variable values
x/20s $rsp            # x : eXamine; 20s : 20 values in string; $rsp : for register RSP (Stack Pointer)
layout next           # show assembly and source code, may need to hit enter a few times
next                  # goes to the next piece of code
nexti                 # goes to the next line of code even if blank
ref                   # refresh the screen to fix layout issues
x/i $pc               # examine the instruction at pc
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











