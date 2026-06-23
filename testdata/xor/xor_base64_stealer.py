import base64, sys
# stage-2: base64( xor(payload, 0x58) )
_blob = "MCwsKCtid3c9LjE0dj0gOTUoND12Ozc1dyssOT89ancoOSE0Nzk8dj0gPQ=="
def deobf(b, k):
    return bytes(c ^ k for c in b)            # XOR decode
url = deobf(base64.b64decode(_blob), 0x58).decode()
sys.stdout.write("beacon " + url)
