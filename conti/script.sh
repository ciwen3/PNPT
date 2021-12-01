#!/bin/bash

OUTPATH="sorted"
F1INPATH="ad_computers.txt"
F2INPATH="ad_users.txt"
F2OUTPATH="ad_users_result.txt"

mkdir "$OUTPATH"

while read p; do

  if [[ ${p:0:17} == ">operatingSystem:" ]]; then
    OSPATH=${p:18}
  fi
  
  if [[ ${p:0:13} == ">dNSHostName:" ]]; then
    if [[ ${OSPATH:0:14} == "Windows Server" ]]; then
      echo ${p:14} >> "$OUTPATH/SERVERS.txt"
      tmp=$(echo "$OSPATH" | cut -d' ' -f1-3)
      echo ${p:14} >> "$OUTPATH/$tmp.txt"
    else
      echo ${p:14} >> "$OUTPATH/WORKERS.txt"
      tmp=$(echo "$OSPATH" | cut -d' ' -f1-2)
      echo ${p:14} >> "$OUTPATH/$tmp.txt"
    fi
  fi
  
done < $F1INPATH



while read p; do

  if [[ ${p:0:13} == ">description:" ]]; then
    DECR=${p:14}
    DECR=${DECR%$'\r'}
  fi

  if [[ ${p:0:16} == ">sAMAccountName:" ]]; then
    ACCNAME=${p:17}
   ACCNAME=${ACCNAME%$'\r'}
    echo "$ACCNAME:$DECR" >> "$OUTPATH/$F2OUTPATH"
  fi
  
  
  
done < $F2INPATH
