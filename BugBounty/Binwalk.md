# Find Flaws in Firmware:
1. Download firmware
2. extract firmware 
```
binwalk -e <filename>.bin
```
3. search for shadow file, the phrase password, secret, uid, username
```
ls -R *shadow*
grep 
strings command to strip out text data
objdump -d -j.text
obj -d -j.rodata
ltrace -e strcmp 
```

## Once everything is extracted grep for interesting stuff: 
```
for i in $ls -R); do 
grep -HanrE "([^A-Z0-9]|^)(AKIA|A3T|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{12,}" $i;
grep -HnroE "([^A-Za-z0-9+/]|^)(eyJ|YTo|Tzo|PD[89]|aHR0cHM6L|aHR0cDo|rO0)[%a-zA-Z0-9+/]+={0,2}"  $i;
grep -HnriE "Access-Control-Allow"  $i;
grep -Hnri "firebaseio.com"  $i;
grep -HnriE "[^a-z0-9_](system|exec|popen|pcntl_exec|eval|create_function|unserialize|file_exists|md5_file|filemtime|filesize|assert) ?\\("  $i;
grep -HnriE "func [a-z0-9_]+\\("  $i;
grep -hrioaE "[a-z0-9_/\\.:-]+@[a-z0-9-]+\\.[a-z0-9.-]+"  $i;
grep -HnroE (([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])"  $i;
grep -harioE "(\\\\?\"|&quot;|%22)[a-z0-9_-]*(api[_-]?key|S3|aws_|secret|passw|auth)[a-z0-9_-]*(\\\\?\"|&quot;|%22): ?(\\\\?\"|&quot;|%22)[^\"&]+(\\\\?\"|&quot;|%22)"  $i;
grep -HanriE "(aws_access|aws_secret|api[_-]?key|ListBucketResult|S3_ACCESS_KEY|Authorization:|RSA PRIVATE|Index of|aws_|secret|ssh-rsa AA)"  $i;
grep -hri "server: "  $i;
grep -HnriE "\u003cinput[^\u003e]+type=[\"']?file[\"']?"  $i;
grep -oriahE "https?://[^\"\\'> ]+"  $i;
grep -HnriE '"django"\|"laravel"\|"symfony"\|"graphite"\|"grafana"\|"X-Drupal-Cache"\|"struts"\|"code ?igniter"\|"cake ?php"\|"grails"\|"elastic ?search"\|"kibana"\|"log ?stash"\|"tomcat"\|"jenkins"\|"hudson"\|"com.atlassian.jira"\|"Apache Subversion"\|"Chef Server"\|"RabbitMQ Management"\|"Mongo"\|"Travis CI - Enterprise"\|"BMC Remedy"\|"artifactory"'  $i;
grep -HnriE '"php warning"\|"php error"\|"fatal error"\|"uncaught exception"\|"include_path"\|"undefined index"\|"undefined variable"\|"\\?php"\|"<\\?[^x]"\|"stack trace\\:"\|"expects parameter [0-9]*"\|"Debug Trace"'  $i;
grep -HnrE '"a:[0-9]+:{"\|"O:[0-9]+:\""\|"s:[0-9]+:\""'  $i;
grep -HnrE '"\\$_(POST|GET|COOKIE|REQUEST|SERVER|FILES)"\|"php://(input|stdin)"'  $i;
grep -hrioaE '"[a-z0-9.-]+\\.s3\\.amazonaws\\.com"\|"[a-z0-9.-]+\\.s3-[a-z0-9-]\\.amazonaws\\.com"\|"[a-z0-9.-]+\\.s3-website[.-](eu|ap|us|ca|sa|cn)"\|"//s3\\.amazonaws\\.com/[a-z0-9._-]+"\|"//s3-[a-z0-9-]+\\.amazonaws\\.com/[a-z0-9._-]+"'  $i;
done
```





4. if needed crack password








# First step, identify where stuff lives in the binary image using binwalk:
```
$ binwalk router-1.2.3.binDECIMAL         HEX             DESCRIPTION-------------------------------------------------------------------------------------------------------20              0x14            gzip compressed data, from Unix, DD-WRT date: Wed Dec 31 18:00:00 1969
```

Ok, so we know that something gziped starts at offset decimal 20 of the image. Lets extract that shall we.
```
$ dd if=router-1.2.3.bin of=router-p1.gzip skip=20 bs=112522993+0 records in12522993+0 records out12522993 bytes transferred in 53.385772 secs (234575 bytes/sec)
```
Ok, now what is this again?
```
$ file router-p1.gzip router-p1.gzip: gzip compressed data, from Unix
```
Ok, good it's a GZIP compressed archive. Lets ungzip it.
```
$ zcat router-p1.gzip > router-p1.imggzip: router-p1.gzip: decompression OK, trailing garbage ignored
```
Now let's see if there is anything behind that.
```
$ binwalk router-p1.img DECIMAL         HEX             DESCRIPTION-------------------------------------------------------------------------------------------------------0               0x0             ELF 64-bit MSB executable, MIPS, MIPS64 rel2 version 1 (SYSV)30715           0x77FB          LZMA compressed data, properties: 0xAA, dictionary size: 759693312 bytes, uncompressed size: 167788804 bytes52267           0xCC2B          LZMA compressed data, properties: 0x9F, dictionary size: 757596160 bytes, uncompressed size: 203637768 bytes(snipped)
```
Awesome! We have a binary, that appears to be MIPS from blocks 0 - 30714. So lets try to extract the squashfs LZMA file system now.
```
$ dd if=router-p1.img of=router-p2.lzma skip=30715 bs=1 15898717+0 records in15898717+0 records out15898717 bytes transferred in 67.454183 secs (235697 bytes/sec)
```
At this point we should be able to mount the file system:
```
$ mount -o loop -t squashfs router-p2.lzma /mnt/tmp
```
Now we can "cd" into /mnt/tmp, we should see the file system root, and from this we can browse and snoop around the file system!
