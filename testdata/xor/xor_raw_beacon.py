import sys
# stage-2 config, single-byte XOR (key 0x58)
_enc = "0,,(+bww=.14v= 95(4=v;75w+,9?=jw(9!479<v= ="
def deobf(s, k):
    return bytes(c ^ k for c in s.encode())   # XOR decode
url = deobf(_enc, 0x58).decode()
sys.stdout.write("beacon " + url)
