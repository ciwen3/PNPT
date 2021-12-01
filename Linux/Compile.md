# Compile C program in Linux for Buffer Overflow
## Create Program
https://royleekiat.medium.com/how-to-perform-a-buffer-overflow-attack-on-a-simple-c-program-linux-x64-dbe5036a61e4

## Disable ALSR in Linux
```
sudo bash -c 'echo 0 > /proc/sys/kernel/randomize_va_space'
```

## Disable canary:
```
gcc vuln.c -o vuln_disable_canary -fno-stack-protector
```

## Disable DEP:
```
gcc vuln.c -o vuln_disable_dep -z execstack
```

## Disable PIE:
```
gcc vuln.c -o vuln_disable_pie -no-pie
```

## Disable all of protection mechanisms listed above (warning: for local testing only):
```
gcc vuln.c -o vuln_disable_all -fno-stack-protector -z execstack -no-pie
```
```
gcc vuln.c -o vuln_disable_all -fno-stack-protector -z execstack -z norelro -no-pie -D_FORTIFY_SOIURCE=0 -ggdb
```
