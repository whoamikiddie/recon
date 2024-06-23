#!/bin/bash

# Check if domain_name is provided
if [ -z "$1" ]; then
  echo "Usage: $0 <domain_name>"
  exit 1
fi

DOMAIN=$1

# Run assetfinder
echo "[*] Running assetfinder..."
assetfinder -subs-only $DOMAIN >> asset.txt

# Run findomain
echo "[*] Running findomain..."
findomain -t $DOMAIN -u find.txt

# Run subfinder
echo "[*] Running subfinder..."
subfinder -d $DOMAIN -all  -recursive -o sub.txt

# Run sublist3r
echo "[*] Running sublist3r..."
sublist3r -d $DOMAIN -o sublist.txt

# Run crt.sh
echo "[*] Running crt.sh"
curl -s https://crt.sh/\?q\=\pb.deribit.com\&output\=json | jq -r '.[].name_value' | grep -Po '(\w+\.\w+\.\w+)$' | anew sub.txt

# Combine and remove duplicates
echo "[*] Combining results and removing duplicates..."
cat *.txt | sort -u >> dup.txt

# Check if websites are live
echo "[*] Checking live websites with httpx..."
cat dup.txt | httpx-toolkit  -ports 80,8080,8000,8888 -threads 200 > live.txt

# Run naabu
echo "[*] Running naabu for port scanning..."
naabu -l dup.txt  -c 50 -nmap-cli 'nmap -sV -sC' -o scan.txt

echo "[*] Running dirsearch for hidden directory "
dirsearch -l live.txt -i 200,204,403 -x 500,502,429 -R 5 --random-agent -t 50 -F -w /home/oxygen/code/python-tools-practice/python/recon/oneListForall/onelistforallshort.txt -o directory.txt


echo "[*] Running a gau  "
cat live.txt | gau > gau.txt

echo "[*] Runnning a uro "
cat gau.txt | uro > filter.txt

echo "[*] running a grep"
cat filter.txt | grep ".js$" > jsfiles.txt


cat  jsfiles.txt | while read url; do python3 /home/oxygen/tools/secretfinder/SecretFinder.py -i $url -o cli >> secret.txt; done

echo "[*] Live check completed."


